#include<iostream>
using namespace std;

int n = 3;
int array[] = {1,1,2};
int cnt[10] = {0,2,1,0,0,0,0,0,0,0};
int used[10] = {0};

int arr[10];
void print(){
    for( int i = 0; i < n; i++ ){
        cout<<arr[i]<<" ";
    }
    cout<<endl;
    return;
}

void pl( int cur ){
    if( cur == n ){
        print();
        return;
    }
    for( int i = 0; i < n; i++ ){
        if( used[i] >= cnt[array[i]] )
            continue;
        if( (array[i] != 0) && (array[i] == array[i - 1]) )
            continue;
        used[i]++;
        arr[cur] = array[i];
        pl( cur + 1 );
        used[i]--;
    }

    return;
}

int len = 4
int prev[] = {1,3,7,4};

void next(){
    int i = len - 1;
    for( ; i >= 1; i-- ){
    
    }

}
