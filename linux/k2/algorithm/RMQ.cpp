#include<iostream>
using namespace std;


int n = 16;
int arr[16] = {124,112,86,130,66,99,37,168,109,202,79,26,185,57,237,89};

int nRMQ = 64;
int RMQ[64];

int rmq_align( int size ){

    //
    return 16;
}

int rmq_init( int *arr,int left,int right,int idx ){
    //nRMQ = rmq_align(n);

    if( left == right ){
        RMQ[idx] = arr[left];
        return arr[left];
    }

    int mid = (left + right)/2;

    int leftMin = rmq_init( arr,left,mid,2 * idx + 1 );
    int rightMin = rmq_init( arr,mid + 1,right,2 * idx + 2 );

    RMQ[ idx ] = leftMin<rightMin?leftMin:rightMin;

    return RMQ[idx];


    return 0;
}


int rmq_query_entity( int idx,int rmqleft,int rmqright,int left,int right ){
    int r1 = rmqleft > right;
    int r2 = rmqright < left;
    if( r1 || r2 )
        return 0x3f3f3f3f;
    if( (right >= rmqright) && (left <= rmqleft) )
        return RMQ[idx];

    int mid = (rmqleft + rmqright)/2;
    int leftMin = rmq_query_entity( 2*idx+1,rmqleft,mid,left,right );
    int rightMin = rmq_query_entity( 2*idx+2,mid + 1,rmqright,left,right );

    return leftMin<rightMin?leftMin:rightMin;
}


int rmq_query( int left,int right ){
    return rmq_query_entity(0,0,n-1,left,right);
}

int rmq_update( int k,int newval ){

    int left = 0;
    int right = n - 1;
    int idx = 0;

    while( left != right ){
        if( newval < RMQ[idx] )
            RMQ[idx] = newval;
        int mid = (left + right)/2;

        if( k <= mid ){
            right = mid;
            idx = idx * 2 + 1;
        }else{
            left = mid + 1;
            idx = idx * 2 + 2;
        }
    }

    RMQ[idx] = newval;

    return 0;
}

void print(){
    int i = 0;
    for( ; i < 16; i++ ){
        printf("%d ",RMQ[15 + i]);
    }
    printf("\n");
}

#if 0

    一棵树,有如下遍历方式
    先序遍历，在返回自身后再访问一次，以此方式遍历后得到一个序列P
    而u到v的过程中，最顶端结点就是LCA(u,v)
    而如果按照先序遍历的顺序重新为设置序号，那么，，LCA（u，v）的序号肯定小于u,v的序号,那么就转为RMQ问题了

    Tarjan算法求LCA(u,e)

        Tarjan(u)                   //marge和find为并查集合并函数和查找函数
    　　 {
        　      for each(u,v)        //访问所有u子节点v
            　　{
                　　          Tarjan(v);        //继续往下遍历
                　　          merge(u,v);      //合并v到u上
                　　          标记v被访问过;
                }
        　　    for each(u,e)        //访问所有和u有询问关系的e
            　　{
                　　         如果e被访问过;
                　　         u,e的最近公共祖先为find(e);
                }
     　　 }
     从根结点开始，必定先走到其中一个结点，设为x，这条路径一定是从lca开始分叉的，而在进入x后，需要返回，此时merge起作用，开始合并，
     一直合并到lca，此时par(x) = lca,在入第二个结点y

     倍增法
     grand[idx][i] 第idx结点向上走2^i步走到的结点
     gw[idx][i] idx结点向上跳2^i的距离
     先将u,v调整到相同高度,然后用倍增法求解


#endif
        int N;

        int trip[64];
        int depth[64];
        int First[64];
        int n2s[64];
        int s2n[64];

        int nexts;
        void prev( int here,int d ){
            n2s[ here ] = nexts;
            s2n[ nexts ] = here;
            nexts++;

            First[ here ] = nexts;
            depth[ here ] = d;

        }


int main(){

    rmq_init( arr,0,15,0 );

    rmq_update( 3,27 );

    cout<<rmq_query(0,15)<<endl;
    print();


    return 0;
}

/*
    1.你们不要再骂PGOne了，万一他急了把我和吴亦凡的事爆出来怎么办.....上一次小G娜曝李小璐传短信的时候我就很担心。
    8.李小璐不是喜欢黑怕么。以后再有dissPG1，主咖就是她了。
    我忽然想起来，小G娜和吴亦凡的事情爆出来的时候，他就说过：李小璐给吴亦凡发暧昧语音暧昧短信，现在想想还真的有可能呢？
    你们想下李小璐之前的绯闻男友，韩庚，蒲巴甲，李晨？他们是一个类型吗？不是吧……

    今天有人用一百块向黄毅清问了怎么看贾乃亮被绿的问题，这个问题，他是这么回答的：

    */
