#include<stdio.h>

//edi
int fun1(int a){
	a++;
	return a;
}

//edi,esi
int fun2(int a,int b){
	a += 1;
	b += 2;
	return a + b;
}

//edi,esi,edx
int fun3(int a,int b,int c){
	a += 1;
	b += 2;
	c += 3;
	return a + b + c;
}

//edi,esi,edx,ecx
int fun4(int a,int b,int c,int d){
	a += 1;
	b += 2;
	c += 3;
	d += 4;
	return a + b + c + d;
}

//edi,esi,edx,ecx,r8d
int fun5(int a,int b,int c,int d,int e){
	a += 1;
	b += 2;
	c += 3;
	d += 4;
	e += 5;
	return a + b + c + d + e;
}

//edi,esi,edx,ecx,r8d,r9d
int fun6(int a,int b,int c,int d,int e,int f){
	a += 1;
	b += 2;
	c += 3;
	d += 4;
	e += 5;
	f += 6;
	return a + b + c + d + e + f;
}

//edi,esi,edx,ecx,r8d,r9d,push
int fun7(int a,int b,int c,int d,int e,int f,int g){
	a += 1;
	b += 2;
	c += 3;
	d += 4;
	e += 5;
	f += 6;
	g += 7;
	return a + b + c + d + e + f + g;
}

int main(){
	asm volatile("nop":::);
	fun1(1);
	asm volatile("nop":::);
	fun2(1,2);
	asm volatile("nop":::);
	fun3(1,2,3);
	asm volatile("nop":::);
	fun4(1,2,3,4);
	asm volatile("nop":::);
	fun5(1,2,3,4,5);
	asm volatile("nop":::);
	fun6(1,2,3,4,5,6);
	asm volatile("nop":::);
	fun7(1,2,3,4,5,6,7);
	return 0;
}
