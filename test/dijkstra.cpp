#include"heap.cpp"
#include<cstring>
#include<unistd.h>
#include<cstdlib>
#define N 10
#define INF 0x3f3f3f3f

int G[N][N];
int d[N];
int vis[N];

int n = 5;

int fun( int a,int b ){
    return a - b;
}

void dijkstra( int from ){
    memset( d,0x3f3f3f3f,sizeof(d) );

    d[from] = 0;
    int min,v;
    while(1){
        min = INF;
        v = -1;
        for( int i = 0; i < n; i++ ){
            if( !vis[i] && d[i] < min ){
                v = i;
                min = d[i];
            }
        }
        if( v == -1 )
            break;

        vis[v] = 1;
        for( int i = 0; i < n; i++ ){
            if( G[v][i] ){
                int t = d[v] + G[v][i];
                if( d[i] > t )
                    d[i] = t;
            }
        }

    }
    return;
}

//pair<nodenum,distance>
int comp( pair<int,int> a,pair<int,int> b){
    return a.second - b.second;
}
void dijkstra_prio( int from ){
    Heap<pair<int,int> > heap(comp);

    memset( d,0x3f3f3f3f,sizeof(d) );

    d[from] = 0;
    pair<int,int> start(from,0);
    heap.push(start);

    while(1){
        if( !heap.size() )
            break;

        pair<int,int> cur;
        while(1){
            if( !heap.size() )
                break;
            cur = heap.pop();
            if( !vis[cur.first] )
                break;
        }

        int v = cur.first;
        vis[v] = 1;
        for( int i = 0; i < n; i++ ){
            if( G[v][i] && !vis[i] ){
                int t = d[v] + G[v][i];
                if( d[i] > t ){
                    d[i] = t;
                    heap.push(pair<int,int>(i,t));
                }
            }
        }

    }


    return;
}

int main(){
    dijkstra_prio(0);
    cout<<d[0]<<endl;
    cout<<d[1]<<endl;
    cout<<d[2]<<endl;
    cout<<d[3]<<endl;
    cout<<d[4]<<endl;

    return 0;
}
