#include"heap.cpp"
#include<cstring>
#include<cstdlib>

#define N 10
int G[N][N]
int vis[N];
int n;

int comp( pair<int,int> a,pair<int,int> b){
    return a.second - b.second;
}

int prim(){

    int ret = 0;
    Heap<pair<int,int> > heap(comp);

    pair<int,int> tmp;
    for( int i = 0; i < n; i++ ){
        if( G[0][i] ){
            heap.push( pair<int,int>(i,G[0][i]) );
        }
    }
    vis[0] = 1;

    while( heap.size() ){
        tmp = heap.pop();
        if( vis[tmp.first] )
            continue;

        int v = tmp.first;
        ret += tmp.second;
        vis[v] = 1;

        for( int i = 0; i < n; i++ ){
            if( G[v][i] ){
                heap.push( pair<int,int>(i,G[v][i]) );
            }
        }
    }

    return ret;
}

int main(){
    cout<<prim()<<endl;
}
