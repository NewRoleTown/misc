#include<iostream>
#include<algorithm>
#include<vector>
using namespace std;
#define N 20

int W,H;
int xs[128],xe[128],ys[128],ye[128];

unsigned char G[N*3][N*3];


int compress( int *x_start,int *x_end,int width ){
    vector<int> x_compress;

    //将坐标本身，左边空白，右边空白入数组
    for( int i = 0; i < N; i++ ){
        for( int d = -1; d <= 1; d++ ){
            int tx1 = x_start[i] + d;
            int tx2 = x_end[i] + d;
            if( tx1 >= 0 && tx1 < W )
                x_compress.push_back(tx1);
            if( tx2 >= 0 && tx2 < W )
                x_compress.push_back(tx2);
        }
    }

    //排序去重
    sort( x_compress.begin(),x_compress.end() );
    x_compress.erase( unique(x_compress.begin(),x_compress.end()),x_compress.end() );

    for( int i = 0; i < N; i++ ){
        x_start[i] = find(x_compress.begin(),x_compress.end(),x_start[i]) - x_compress.begin();
        x_end[i] = find(x_compress.begin(),x_compress.end(),x_end[i]) - x_compress.begin();
    }

    return x_compress.size();
}


int main(){

    W = compress( xs,xe,W );
    H = compress( ys,ye,H );

    return 0;

}
