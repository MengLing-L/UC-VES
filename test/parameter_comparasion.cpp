#include <HsFFI.h>
#ifdef __GLASGOW_HASKELL__
#include "/root/Three-Square/3squares-ffi_stub.h"
#endif
#include <stdio.h>
#include <iostream>
using namespace std;

int main(int argc, char *argv[])
{
    unsigned long int *i;
    hs_init(&argc, &argv);
    auto start_time = chrono::steady_clock::now();
    i = static_cast<unsigned long int *>(get_three_squares(18884));
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "Three square takes time = "
        << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    cout << *(i+2) << endl;

    hs_exit();
    return 0;
}