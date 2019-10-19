#include <iostream>
using namespace std;
int n,s,a,b;
int yi[5000],xi[5000];


int minpower(){

    int ret = -1;
    int p=0,q=5000;

    for(p=0;p<n;p++){
        if(yi[p]<=q){
            q=yi[p];
            ret = p;
        }
    }

    return ret;

}



int main(){
    cin>>n>>s;
    cin>>a>>b;
    int p,q;
    for(p=0;p<n;p++){
        cin>>xi[p]>>yi[p];
    }


    int i=0,e=0;
    for(i=0;i<n;i++){
		int t = minpower();
        if( (a+b) >= (xi[minpower()])){
			if( s < yi[minpower()] )
				break;
            e++;
			s -= yi[minpower()];
        }
        yi[minpower()]=1001;
    }
    cout<<e<<endl;
    return 0;
}







