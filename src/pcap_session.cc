#include <assert.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <cstring>
#include <string.h>
#include <v8.h>
#include <nan.h>
#include "pcap_session.h"

using namespace v8;

Nan::Persistent<Function> PcapSession::constructor;

PcapSession::PcapSession() : pcap_handle(nullptr), pcap_dump_handle(nullptr), buffer_data(nullptr), buffer_length(0), header_data(nullptr) {}
PcapSession::~PcapSession() {
    if (pcap_dump_handle != nullptr) {
        pcap_dump_close(pcap_dump_handle);
    }
    if (pcap_handle != nullptr) {
        pcap_close(pcap_handle);
    }
}

void PcapSession::Init(Local<Object> exports) {
    Nan::HandleScope scope;

    Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
    tpl->SetClassName(Nan::New("PcapSession").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    Nan::SetPrototypeMethod(tpl, "open_live", OpenLive);
    Nan::SetPrototypeMethod(tpl, "open_offline", OpenOffline);
    Nan::SetPrototypeMethod(tpl, "dispatch", Dispatch);
    Nan::SetPrototypeMethod(tpl, "fileno", Fileno);
    Nan::SetPrototypeMethod(tpl, "close", Close);
    Nan::SetPrototypeMethod(tpl, "stats", Stats);
    Nan::SetPrototypeMethod(tpl, "inject", Inject);

    constructor.Reset(tpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked());
    exports->Set(Nan::GetCurrentContext(), Nan::New("PcapSession").ToLocalChecked(), tpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked()).FromJust();
}

void PcapSession::New(const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;
    if (info.IsConstructCall()) {
        PcapSession* obj = new PcapSession();
        obj->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    } else {
        Local<Function> cons = Nan::New<Function>(constructor);
        info.GetReturnValue().Set(cons->NewInstance(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
    }
}

void PcapSession::PacketReady(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Nan::HandleScope scope;

    PcapSession* session = reinterpret_cast<PcapSession *>(s);

    if (session->pcap_dump_handle != nullptr) {
        pcap_dump(reinterpret_cast<u_char *>(session->pcap_dump_handle), pkthdr, packet);
    }

    size_t copy_len = pkthdr->caplen;
    if (copy_len > session->buffer_length) {
        copy_len = session->buffer_length;
    }
    memcpy(session->buffer_data, packet, copy_len);

    // Copy header data to fixed offsets in second buffer from user
    memcpy(session->header_data, &(pkthdr->ts.tv_sec), sizeof(pkthdr->ts.tv_sec));
    memcpy(session->header_data + 4, &(pkthdr->ts.tv_usec), sizeof(pkthdr->ts.tv_usec));
    memcpy(session->header_data + 8, &(pkthdr->caplen), sizeof(pkthdr->caplen));
    memcpy(session->header_data + 12, &(pkthdr->len), sizeof(pkthdr->len));

    Nan::TryCatch try_catch;

    // Create a Nan::Callback from the stored function
    v8::Local<v8::Function> callback = Nan::New<v8::Function>(session->packet_ready_cb);

    // Create the argument list
    Local<Value> argv[] = { Nan::Undefined() };

    // Use Nan::Callback to make the call
    Nan::Call(callback, Nan::GetCurrentContext()->Global(), 1, argv);

    if (try_catch.HasCaught()) {
        Nan::FatalException(try_catch);
    }
}

void PcapSession::Dispatch(const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;

    if (info.Length() != 2) {
        Nan::ThrowTypeError("Dispatch takes exactly two arguments");
        return;
    }

    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("First argument must be a buffer");
        return;
    }

    if (!node::Buffer::HasInstance(info[1])) {
        Nan::ThrowTypeError("Second argument must be a buffer");
        return;
    }

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.This());

    Local<Object> buffer_obj = info[0]->ToObject(Nan::GetCurrentContext()).ToLocalChecked();
    session->buffer_data = node::Buffer::Data(buffer_obj);
    session->buffer_length = node::Buffer::Length(buffer_obj);
    Local<Object> header_obj = info[1]->ToObject(Nan::GetCurrentContext()).ToLocalChecked();
    session->header_data = node::Buffer::Data(header_obj);

    int packet_count;
    do {
        packet_count = pcap_dispatch(session->pcap_handle, 1, PacketReady, reinterpret_cast<u_char *>(session));
    } while (packet_count > 0);

    info.GetReturnValue().Set(Nan::New<v8::Integer>(packet_count));
}

void PcapSession::Open(bool live, const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (info.Length() != 7) {
        Nan::ThrowTypeError("Open requires 7 arguments");
        return;
    }

    if (!info[0]->IsString()) {
        Nan::ThrowTypeError("Argument 0 must be a string");
        return;
    }
    if (!info[1]->IsString()) {
        Nan::ThrowTypeError("Argument 1 must be a string");
        return;
    }
    if (!info[2]->IsInt32()) {
        Nan::ThrowTypeError("Argument 2 must be a number");
        return;
    }
    if (!info[3]->IsString()) {
        Nan::ThrowTypeError("Argument 3 must be a string");
        return;
    }
    if (!info[4]->IsFunction()) {
        Nan::ThrowTypeError("Argument 4 must be a function");
        return;
    }
    if (!info[5]->IsBoolean()) {
        Nan::ThrowTypeError("Argument 5 must be a boolean");
        return;
    }
    if (!info[6]->IsInt32()) {
        Nan::ThrowTypeError("Argument 6 must be a number");
        return;
    }

    Nan::Utf8String device(info[0]->ToString(Nan::GetCurrentContext()).ToLocalChecked());
    Nan::Utf8String filter(info[1]->ToString(Nan::GetCurrentContext()).ToLocalChecked());
    int buffer_size = info[2]->Int32Value(Nan::GetCurrentContext()).FromJust();
    int timeout = info[6]->Int32Value(Nan::GetCurrentContext()).FromJust();
    Nan::Utf8String pcap_output_filename(info[3]->ToString(Nan::GetCurrentContext()).ToLocalChecked());

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.This());

    session->packet_ready_cb.Reset(info[4].As<Function>());
    session->pcap_dump_handle = nullptr;

    if (live) {
        if (pcap_lookupnet(*device, &session->net, &session->mask, errbuf) == -1) {
            session->net = 0;
            session->mask = 0;
            fprintf(stderr, "Warning: %s - this may not actually work\n", errbuf);
        }

        session->pcap_handle = pcap_create(*device, errbuf);
        if (session->pcap_handle == nullptr) {
            Nan::ThrowError(errbuf);
            return;
        }

        if (pcap_set_snaplen(session->pcap_handle, 65535) != 0) {
            Nan::ThrowError("Error setting snaplen");
            return;
        }

        if (pcap_set_promisc(session->pcap_handle, 1) != 0) {
            Nan::ThrowError("Error setting promiscuous mode");
            return;
        }

        if (pcap_set_buffer_size(session->pcap_handle, buffer_size) != 0) {
            Nan::ThrowError("Error setting buffer size");
            return;
        }

        if (pcap_set_timeout(session->pcap_handle, timeout) != 0) {
            Nan::ThrowError("Error setting read timeout");
            return;
        }

        if (info[5]->BooleanValue(Nan::GetCurrentContext()->GetIsolate())) {
            if (pcap_set_rfmon(session->pcap_handle, 1) != 0) {
                Nan::ThrowError(pcap_geterr(session->pcap_handle));
                return;
            }
        }

        if (pcap_activate(session->pcap_handle) != 0) {
            Nan::ThrowError(pcap_geterr(session->pcap_handle));
            return;
        }

        if (strlen(*pcap_output_filename) > 0) {
            session->pcap_dump_handle = pcap_dump_open(session->pcap_handle, *pcap_output_filename);
            if (session->pcap_dump_handle == nullptr) {
                Nan::ThrowError("Error opening dump file");
                return;
            }
        }

        if (pcap_setnonblock(session->pcap_handle, 1, errbuf) == -1) {
            Nan::ThrowError(errbuf);
            return;
        }
    } else {
        session->pcap_handle = pcap_open_offline(*device, errbuf);
        if (session->pcap_handle == nullptr) {
            Nan::ThrowError(errbuf);
            return;
        }
    }

    if (filter.length() != 0) {
        if (pcap_compile(session->pcap_handle, &session->fp, *filter, 1, session->net) == -1) {
            Nan::ThrowError(pcap_geterr(session->pcap_handle));
            return;
        }

        if (pcap_setfilter(session->pcap_handle, &session->fp) == -1) {
            Nan::ThrowError(pcap_geterr(session->pcap_handle));
            return;
        }
        pcap_freecode(&session->fp);
    }

#if defined(__APPLE_CC__) || defined(__APPLE__)
    #include <net/bpf.h>
    int fd = pcap_get_selectable_fd(session->pcap_handle);
    int v = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &v) == -1) {
        Nan::ThrowError("Error setting BIOCIMMEDIATE");
        return;
    }
#endif

    int link_type = pcap_datalink(session->pcap_handle);

    Local<Value> ret;
    switch (link_type) {
        case DLT_NULL:
            ret = Nan::New("LINKTYPE_NULL").ToLocalChecked();
            break;
        case DLT_EN10MB:
            ret = Nan::New("LINKTYPE_ETHERNET").ToLocalChecked();
            break;
        case DLT_IEEE802_11_RADIO:
            ret = Nan::New("LINKTYPE_IEEE802_11_RADIO").ToLocalChecked();
            break;
        case DLT_RAW:
            ret = Nan::New("LINKTYPE_RAW").ToLocalChecked();
            break;
        case DLT_LINUX_SLL:
            ret = Nan::New("LINKTYPE_LINUX_SLL").ToLocalChecked();
            break;
        default:
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
            ret = Nan::New(errbuf).ToLocalChecked();
            break;
    }
    info.GetReturnValue().Set(ret);
}

void PcapSession::OpenLive(const Nan::FunctionCallbackInfo<Value>& info) {
    return Open(true, info);
}

void PcapSession::OpenOffline(const Nan::FunctionCallbackInfo<Value>& info) {
    return Open(false, info);
}

void PcapSession::Close(const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    if (session->pcap_dump_handle != nullptr) {
        pcap_dump_close(session->pcap_dump_handle);
        session->pcap_dump_handle = nullptr;
    }

    if (session->pcap_handle != nullptr) {
        pcap_close(session->pcap_handle);
        session->pcap_handle = nullptr;
    }
    session->packet_ready_cb.Reset();
}

void PcapSession::Fileno(const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    int fd = pcap_get_selectable_fd(session->pcap_handle);

    info.GetReturnValue().Set(Nan::New<v8::Integer>(fd));
}

void PcapSession::Stats(const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;

    struct pcap_stat ps;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    if (pcap_stats(session->pcap_handle, &ps) == -1) {
        Nan::ThrowError("Error in pcap_stats");
        return;
    }

    Local<Object> stats_obj = Nan::New<Object>();

    stats_obj->Set(Nan::GetCurrentContext(), Nan::New("ps_recv").ToLocalChecked(), Nan::New<v8::Integer>(ps.ps_recv)).FromJust();
    stats_obj->Set(Nan::GetCurrentContext(), Nan::New("ps_drop").ToLocalChecked(), Nan::New<v8::Integer>(ps.ps_drop)).FromJust();
    stats_obj->Set(Nan::GetCurrentContext(), Nan::New("ps_ifdrop").ToLocalChecked(), Nan::New<v8::Integer>(ps.ps_ifdrop)).FromJust();

    info.GetReturnValue().Set(stats_obj);
}

void PcapSession::Inject(const Nan::FunctionCallbackInfo<Value>& info) {
    Nan::HandleScope scope;

    if (info.Length() != 1) {
        Nan::ThrowTypeError("Inject takes exactly one argument");
        return;
    }

    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("Argument must be a buffer");
        return;
    }

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());
    Local<Object> buffer_obj = info[0]->ToObject(Nan::GetCurrentContext()).ToLocalChecked();
    char *bufferData = node::Buffer::Data(buffer_obj);
    size_t bufferLength = node::Buffer::Length(buffer_obj);

    if (pcap_inject(session->pcap_handle, bufferData, bufferLength) != static_cast<int>(bufferLength)) {
        Nan::ThrowError("Pcap inject failed.");
        return;
    }
    return;
}
