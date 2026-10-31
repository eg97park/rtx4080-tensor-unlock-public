/* SPDX-License-Identifier: GPL-2.0-only
 * Native Windows measurement, sm_89 only. No MMIO/PCI/reset/clock controls.
 * GPU execution requires --run; building/disassembly never executes kernels.
 */
#define NOMINMAX
#include <windows.h>
#include <cuda_runtime.h>
#include <cuda_fp16.h>
#include <cuda_bf16.h>
#include <cublas_v2.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include "reference.h"

static void ck(cudaError_t status) {
    if (status != cudaSuccess) throw std::runtime_error(cudaGetErrorString(status));
}
static void cb(cublasStatus_t status) {
    if (status != CUBLAS_STATUS_SUCCESS) throw std::runtime_error("cuBLAS status " + std::to_string(int(status)));
}
struct Buffer {
    void *p=nullptr;
    explicit Buffer(size_t bytes) { ck(cudaMalloc(&p,bytes)); }
    ~Buffer() { if(p) cudaFree(p); }
    Buffer(const Buffer&)=delete;
};
struct Event {
    cudaEvent_t e=nullptr;
    Event() { ck(cudaEventCreate(&e)); }
    ~Event() { if(e) cudaEventDestroy(e); }
};
struct Blas {
    cublasHandle_t h=nullptr;
    Blas() { cb(cublasCreate(&h)); }
    ~Blas() { if(h) cublasDestroy(h); }
};
static float median(std::vector<float> values) {
    std::sort(values.begin(),values.end()); return values[values.size()/2];
}
static void timings(const std::vector<float>& values) {
    std::printf("\"samples_ms\":[");
    for(size_t i=0;i<values.size();++i) std::printf("%s%.9g",i?",":"",double(values[i]));
    std::printf("],\"median_ms\":%.9g",double(median(values)));
}
static void loaded_dlls() {
    std::printf("\"dll_paths\":{");
    const char* names[]={"cublas64_13.dll","cublasLt64_13.dll"};
    for(int i=0;i<2;++i) {
        char path[32768]={}; HMODULE module=GetModuleHandleA(names[i]);
        DWORD length=module?GetModuleFileNameA(module,path,sizeof(path)):0;
        if(!length||length>=sizeof(path)) throw std::runtime_error("cuBLAS module location unavailable");
        std::printf("%s\"%s\":\"",i?",":"",names[i]);
        for(DWORD j=0;j<length;++j){if(path[j]=='\\'||path[j]=='\"')std::putchar('\\');std::putchar(path[j]);}
        std::putchar('"');
    }
    std::putchar('}');
}

template<int Mode> __global__ void issue(unsigned iters, float *out) {
    float d[8][4] = {};
    unsigned one = Mode==0 ? 0x3c003c00u : (Mode==1 ? 0x3f803f80u : 0x3f800000u);
    for(unsigned i=0;i<iters;++i) {
#pragma unroll
        for(int j=0;j<8;++j) {
            if constexpr(Mode==0) asm volatile(
                "mma.sync.aligned.m16n8k16.row.col.f32.f16.f16.f32 "
                "{%0,%1,%2,%3},{%4,%5,%6,%7},{%8,%9},{%0,%1,%2,%3};"
                : "+f"(d[j][0]),"+f"(d[j][1]),"+f"(d[j][2]),"+f"(d[j][3])
                : "r"(one),"r"(one),"r"(one),"r"(one),"r"(one),"r"(one));
            else if constexpr(Mode==1) asm volatile(
                "mma.sync.aligned.m16n8k16.row.col.f32.bf16.bf16.f32 "
                "{%0,%1,%2,%3},{%4,%5,%6,%7},{%8,%9},{%0,%1,%2,%3};"
                : "+f"(d[j][0]),"+f"(d[j][1]),"+f"(d[j][2]),"+f"(d[j][3])
                : "r"(one),"r"(one),"r"(one),"r"(one),"r"(one),"r"(one));
            else asm volatile(
                "mma.sync.aligned.m16n8k8.row.col.f32.tf32.tf32.f32 "
                "{%0,%1,%2,%3},{%4,%5,%6,%7},{%8,%9},{%0,%1,%2,%3};"
                : "+f"(d[j][0]),"+f"(d[j][1]),"+f"(d[j][2]),"+f"(d[j][3])
                : "r"(one),"r"(one),"r"(one),"r"(one),"r"(one),"r"(one));
        }
    }
    float sum=0;
#pragma unroll
    for(int j=0;j<8;++j) for(int e=0;e<4;++e) sum+=d[j][e];
    out[blockIdx.x*blockDim.x+threadIdx.x]=sum;
}
static void run_issue(int blocks,int reps) {
    constexpr unsigned iters=4096,threads=256;
    Buffer output(size_t(blocks)*threads*sizeof(float));
    std::vector<float> host(size_t(blocks)*threads), times;
    Event start,stop;
    const char *names[]={"f16_f32","bf16_f32","tf32"};
    for(int mode=0;mode<3;++mode) {
        auto launch=[&] {
            if(mode==0) issue<0><<<blocks,threads>>>(iters,(float*)output.p);
            else if(mode==1) issue<1><<<blocks,threads>>>(iters,(float*)output.p);
            else issue<2><<<blocks,threads>>>(iters,(float*)output.p);
            ck(cudaGetLastError());
        };
        times.clear(); launch(); launch(); ck(cudaDeviceSynchronize());
        for(int r=0;r<reps;++r) {
            ck(cudaEventRecord(start.e)); launch(); ck(cudaEventRecord(stop.e)); ck(cudaEventSynchronize(stop.e));
            float ms; ck(cudaEventElapsedTime(&ms,start.e,stop.e));
            if(!(ms>0) || !std::isfinite(ms)) throw std::runtime_error("invalid event time");
            times.push_back(ms);
            ck(cudaMemcpy(host.data(),output.p,host.size()*sizeof(float),cudaMemcpyDeviceToHost));
            float expected=float(iters*(mode==2?8:16)*32);
            for(float value:host) if(value!=expected) throw std::runtime_error("MMA sink validation failed");
        }
        double ops=double(blocks)*(threads/32)*iters*8*2*16*8*(mode==2?8:16);
        std::printf("%s{\"mode\":\"%s\",\"kind\":\"mma_issue\",\"blocks\":%d,\"threads\":256,\"iters\":4096,\"chains\":8,",mode?",":"",names[mode],blocks);
        timings(times);
        std::printf(",\"tflops\":%.9g,\"accuracy_pass\":true,\"all_sinks_checked_each_repeat\":true}",ops/(median(times)*1e9));
    }
}

static void run_gemm(int m,int n,int k,int reps,uint32_t seed) {
    const char *names[]={"f16_f32","bf16_f32","tf32","fp32_pedantic"};
    Blas blas;
    cb(cublasSetAtomicsMode(blas.h,CUBLAS_ATOMICS_NOT_ALLOWED));
    for(int mode=0;mode<4;++mode) {
        bool tf32=mode==2;
        std::vector<float> a(size_t(m)*k),b(size_t(k)*n),c(size_t(m)*n);
        for(size_t i=0;i<a.size();++i) a[i]=reference::input(i,seed);
        for(size_t i=0;i<b.size();++i) b[i]=reference::input(i,seed^0x4080);
        std::vector<__half> ah,bh;
        std::vector<__nv_bfloat16> ab,bb;
        void *ha=a.data(),*hb=b.data(); size_t width=sizeof(float);
        cudaDataType_t type=CUDA_R_32F;
        if(mode==0) {
            ah.resize(a.size());bh.resize(b.size());
            for(size_t i=0;i<a.size();++i){ah[i]=__float2half_rn(a[i]);a[i]=__half2float(ah[i]);}
            for(size_t i=0;i<b.size();++i){bh[i]=__float2half_rn(b[i]);b[i]=__half2float(bh[i]);}
            ha=ah.data();hb=bh.data();width=2;type=CUDA_R_16F;
        } else if(mode==1) {
            ab.resize(a.size());bb.resize(b.size());
            for(size_t i=0;i<a.size();++i){ab[i]=__float2bfloat16_rn(a[i]);a[i]=__bfloat162float(ab[i]);}
            for(size_t i=0;i<b.size();++i){bb[i]=__float2bfloat16_rn(b[i]);b[i]=__bfloat162float(bb[i]);}
            ha=ab.data();hb=bb.data();width=2;type=CUDA_R_16BF;
        }
        Buffer da(a.size()*width),db(b.size()*width),dc(c.size()*sizeof(float));
        ck(cudaMemcpy(da.p,ha,a.size()*width,cudaMemcpyHostToDevice));
        ck(cudaMemcpy(db.p,hb,b.size()*width,cudaMemcpyHostToDevice));
        const float alpha=1,beta=0;
        cublasComputeType_t compute=mode==3?CUBLAS_COMPUTE_32F_PEDANTIC:(tf32?CUBLAS_COMPUTE_32F_FAST_TF32:CUBLAS_COMPUTE_32F);
        cb(cublasSetMathMode(blas.h,mode==3?CUBLAS_PEDANTIC_MATH:CUBLAS_MATH_DISALLOW_REDUCED_PRECISION_REDUCTION));
        auto launch=[&] { cb(cublasGemmEx(blas.h,CUBLAS_OP_N,CUBLAS_OP_N,m,n,k,
            &alpha,da.p,type,m,db.p,type,k,&beta,dc.p,CUDA_R_32F,m,compute,CUBLAS_GEMM_DEFAULT)); };
        auto validate=[&] {
            ck(cudaMemcpy(c.data(),dc.p,c.size()*sizeof(float),cudaMemcpyDeviceToHost));
            auto error=reference::validate(a,b,c,m,n,k,tf32);
            if(!reference::pass(error,tf32)) throw std::runtime_error(std::string(names[mode])+" GEMM accuracy failure");
            return error;
        };
        ck(cudaMemset(dc.p,0xff,c.size()*sizeof(float))); launch(); ck(cudaDeviceSynchronize());
        auto initial=validate();
        launch(); launch(); ck(cudaDeviceSynchronize());
        std::vector<float> times; Event start,stop;
        for(int r=0;r<reps;++r) {
            ck(cudaEventRecord(start.e)); launch(); ck(cudaEventRecord(stop.e)); ck(cudaEventSynchronize(stop.e));
            float ms; ck(cudaEventElapsedTime(&ms,start.e,stop.e));
            if(!(ms>0) || !std::isfinite(ms)) throw std::runtime_error("invalid event time");
            times.push_back(ms);
        }
        auto error=validate();
        std::printf("%s{\"kind\":\"gemm\",\"mode\":\"%s\",\"m\":%d,\"n\":%d,\"k\":%d,\"seed\":%u,",mode?",":"",names[mode],m,n,k,seed);
        timings(times);
        std::printf(",\"tflops\":%.9g,\"accuracy_pass\":true,\"checked_per_validation\":%zu,\"validation_runs\":2,\"all_outputs_finite\":true,\"max_abs_error\":%.9g,\"nrmse\":%.9g,\"initial_nrmse\":%.9g}",
            2.0*m*n*k/(median(times)*1e9),error.checked,error.max_absolute,error.nrmse(),initial.nrmse());
    }
}

int main(int argc,char **argv) {
    // Defaults never select a GPU or launch a kernel.
    if(argc<3 || std::strcmp(argv[1],"--run")) {
        std::fprintf(stderr,"Explicit GPU run: windows_bench.exe --run issue REPS | --run gemm M N K REPS SEED\n"); return 2;
    }
    try {
        bool is_issue=!std::strcmp(argv[2],"issue");
        if((is_issue && argc!=4) || (!is_issue && (argc!=8 || std::strcmp(argv[2],"gemm")))) throw std::runtime_error("invalid arguments");
        auto number=[](const char *v,int low,int high){char *end;long x=std::strtol(v,&end,10);if(!*v||*end||x<low||x>high)throw std::runtime_error("argument outside bound");return int(x);};
        int m=0,n=0,k=0,reps=number(argv[is_issue?3:6],3,31);
        uint32_t seed=2704;
        if(!is_issue){m=number(argv[3],1,8192);n=number(argv[4],1,8192);k=number(argv[5],1,8192);seed=uint32_t(number(argv[7],1,1000000));}
        if(std::getenv("NVIDIA_TF32_OVERRIDE") || std::getenv("CUBLAS_EMULATION_STRATEGY")) throw std::runtime_error("unset process math overrides before a controlled run");
        int count=0;ck(cudaGetDeviceCount(&count)); if(count!=1)throw std::runtime_error("expected exactly one CUDA device");
        cudaDeviceProp prop;ck(cudaGetDeviceProperties(&prop,0));
        if(prop.major!=8||prop.minor!=9||std::strcmp(prop.name,"NVIDIA GeForce RTX 4080"))throw std::runtime_error("unexpected CUDA target");
        ck(cudaSetDevice(0));char bus[32]={};ck(cudaDeviceGetPCIBusId(bus,sizeof(bus),0));
        int driver=0,runtime=0,version=0;ck(cudaDriverGetVersion(&driver));ck(cudaRuntimeGetVersion(&runtime));
        {Blas b;cb(cublasGetVersion(b.h,&version));}
        std::printf("{\"schema_version\":1,\"device\":\"NVIDIA GeForce RTX 4080\",\"pci_bus\":\"%s\",\"sm_count\":%d,\"cuda_driver\":%d,\"cuda_runtime\":%d,\"cublas\":%d,\"reps\":%d,\"results\":[",bus,prop.multiProcessorCount,driver,runtime,version,reps);
        if(is_issue) run_issue(prop.multiProcessorCount*4,reps); else run_gemm(m,n,k,reps,seed);
        ck(cudaDeviceSynchronize());std::printf("],");loaded_dlls();std::printf(",\"complete\":true}\n");return 0;
    } catch(const std::exception& e) {std::fprintf(stderr,"Measurement stopped: %s\n",e.what());return 1;}
}
