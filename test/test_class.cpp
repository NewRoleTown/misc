#include<iostream>
using namespace std;

class Base{
	public:
		virtual void add() = 0;
};

class A : public Base{
	public:
		virtual void fx(){
			cout<<"fx"<<endl;
		}
		void add(){
			cout<<"Aadd"<<endl;
		}
};

class B : public Base{
	public:
		virtual void fy(){
			cout<<"fy"<<endl;
		}
		void add(){
			cout<<"Badd"<<endl;
		}
};

class X:public A,public B{
	public:
		void add(){
			cout<<"Xadd"<<endl;
		}	
};

int main(){
	X *p = new X;
	((B*)p)->add();
	return 0;
} 
