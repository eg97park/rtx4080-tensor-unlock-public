#include <cassert>
#include <limits>
#include "../src/bench/reference.h"
int main() {
    const int m=3,n=5,k=7;
    std::vector<float> a(m*k),b(k*n),c(m*n);
    for (size_t i=0;i<a.size();++i) a[i]=reference::input(i,1);
    for (size_t i=0;i<b.size();++i) b[i]=reference::input(i,2);
    for (int j=0;j<n;++j) for(int i=0;i<m;++i) {
        double x=0; for(int p=0;p<k;++p) x+=double(a[i+p*m])*b[p+j*k]; c[i+j*m]=float(x);
    }
    auto good=reference::validate(a,b,c,m,n,k,false);
    assert(good.checked==m*n && reference::pass(good,false));
    c[4]+=1; assert(!reference::pass(reference::validate(a,b,c,m,n,k,false),false));
    c[4]=std::numeric_limits<float>::infinity();
    assert(!reference::pass(reference::validate(a,b,c,m,n,k,true),true));
    c[4]=std::numeric_limits<float>::quiet_NaN();
    assert(!reference::pass(reference::validate(a,b,c,m,n,k,false),false));
    auto large=reference::coordinates(4096,8192);
    assert(large.size()>=1000 && large.front()==0 && large.back()==4096ULL*8192-1);
    assert(reference::input(123,1)==reference::input(123,1));
    return 0;
}
