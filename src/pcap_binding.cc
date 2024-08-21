#include <assert.h>
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "pcap_session.h"

using namespace v8;

// Helper method, convert a sockaddr* (AF_INET or AF_INET6) to a string, and set it as the property
// named 'key' in the Address object you pass in.
#include <pcap/pcap.h>
#include <nan.h>
#include <v8.h>

using namespace v8;

// Helper method, convert a sockaddr* (AF_INET or AF_INET6) to a string, and set it as the property
// named 'key' in the Address object you pass in.
void SetAddrStringHelper(const char* key, sockaddr* addr, Local<Object> Address) {
    if (key && addr) {
        char dst_addr[INET6_ADDRSTRLEN + 1] = {0};
        const char* src = nullptr;
        socklen_t size = 0;
        
        // Determine address family and set src and size accordingly
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in* saddr = (struct sockaddr_in*) addr;
            src = (const char*) &(saddr->sin_addr);
            size = INET_ADDRSTRLEN;
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6* saddr6 = (struct sockaddr_in6*) addr;
            src = (const char*) &(saddr6->sin6_addr);
            size = INET6_ADDRSTRLEN;
        }

        // Convert address to string
        const char* address = inet_ntop(addr->sa_family, src, dst_addr, size);
        
        // Get the current context
        Isolate* isolate = Isolate::GetCurrent();
        Local<Context> context = isolate->GetCurrentContext();

        // Create V8 string objects for key and address
        Local<String> js_key = Nan::New<String>(key).ToLocalChecked();
        Local<String> js_address = Nan::New<String>(address).ToLocalChecked();

        // Set the property on the object
        Address->Set(context, js_key, js_address).FromJust();
    }
}

NAN_METHOD(FindAllDevs) {
    Nan::HandleScope scope;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * cur_dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        Nan::ThrowTypeError(errbuf);
        return;
    }

    Local<Array> DevsArray = Nan::New<Array>();
    Isolate* isolate = Isolate::GetCurrent();
    Local<Context> context = isolate->GetCurrentContext();

    int i = 0;
    for (cur_dev = alldevs; cur_dev != NULL; cur_dev = cur_dev->next, i++) {
        Local<Object> Dev = Nan::New<Object>();

        Dev->Set(context, Nan::New<String>("name").ToLocalChecked(), Nan::New<String>(cur_dev->name).ToLocalChecked()).FromJust();
        if (cur_dev->description != NULL) {
            Dev->Set(context, Nan::New<String>("description").ToLocalChecked(), Nan::New<String>(cur_dev->description).ToLocalChecked()).FromJust();
        }

        Local<Array> AddrArray = Nan::New<Array>();
        int j = 0;
        for (pcap_addr_t* cur_addr = cur_dev->addresses; cur_addr != NULL; cur_addr = cur_addr->next, j++) {
            if (cur_addr->addr) {
                int af = cur_addr->addr->sa_family;
                if (af == AF_INET || af == AF_INET6) {
                    Local<Object> Address = Nan::New<Object>();
                    SetAddrStringHelper("addr", cur_addr->addr, Address);
                    SetAddrStringHelper("netmask", cur_addr->netmask, Address);
                    SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
                    SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
                    AddrArray->Set(context, j, Address).FromJust();
                }
            }
        }

        Dev->Set(context, Nan::New<String>("addresses").ToLocalChecked(), AddrArray).FromJust();

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev->Set(context, Nan::New<String>("flags").ToLocalChecked(), Nan::New<String>("PCAP_IF_LOOPBACK").ToLocalChecked()).FromJust();
        }

        DevsArray->Set(context, i, Dev).FromJust();
    }

    pcap_freealldevs(alldevs);
    info.GetReturnValue().Set(DevsArray);
}

NAN_METHOD(DefaultDevice) {
    Nan::HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t* alldevs, * dev;
    pcap_addr_t* addr;
    bool found = false;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        Nan::ThrowError(errbuf);
        return;
    }

    if (alldevs == NULL) {
        Nan::ThrowError("pcap_findalldevs didn't find any devs");
        return;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
            for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) {
                    info.GetReturnValue().Set(Nan::New<String>(dev->name).ToLocalChecked());
                    found = true;
                    break;
                }
            }

            if (found) {
                break;
            }
        }
    }

    pcap_freealldevs(alldevs);
}

NAN_METHOD(LibVersion) {
    info.GetReturnValue().Set(Nan::New<String>(pcap_lib_version()).ToLocalChecked());
}

void Initialize(Local<Object> exports) {
    Nan::HandleScope scope;

    PcapSession::Init(exports);

    exports->Set(Nan::GetCurrentContext(), Nan::New<String>("findalldevs").ToLocalChecked(), Nan::New<FunctionTemplate>(FindAllDevs)->GetFunction(Nan::GetCurrentContext()).ToLocalChecked()).FromJust();
    exports->Set(Nan::GetCurrentContext(), Nan::New<String>("default_device").ToLocalChecked(), Nan::New<FunctionTemplate>(DefaultDevice)->GetFunction(Nan::GetCurrentContext()).ToLocalChecked()).FromJust();
    exports->Set(Nan::GetCurrentContext(), Nan::New<String>("lib_version").ToLocalChecked(), Nan::New<FunctionTemplate>(LibVersion)->GetFunction(Nan::GetCurrentContext()).ToLocalChecked()).FromJust();
}

NODE_MODULE(pcap_binding, Initialize)

