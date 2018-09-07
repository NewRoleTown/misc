#include<iostream>
#include<cmath>
#include<cstring>
#include<assert.h>
using namespace std;

struct pos{
	int x;
	int y;
};

pos m_points[128];
int m_nNum = 16;

void init(){
	struct pos t = { 309/2, 817/2};
	m_points[0] = t;

	t = { 298/2, 768/2};
	m_points[1] = t;

	t = { 291/2, 751/2};
	m_points[2] = t;

	t = { 291/2, 730/2};
	m_points[3] = t;

	t = { 295/2, 706/2};
	m_points[4] = t;

	t = { 295/2, 680/2};
	m_points[5] = t;

	t = { 312/2, 654/2};
	m_points[6] = t;

	t = { 338/2, 628/2};
	m_points[7] = t;

	t = { 373/2, 625/2};
	m_points[8] = t;

	t = { 409/2, 607/2};
	m_points[9] = t;

	t = { 451/2, 607/2};
	m_points[10] = t;

	t = { 486/2, 605/2};
	m_points[11] = t;

	t = { 516/2, 633/2};
	m_points[12] = t;

	t = { 532/2, 645/2};
	m_points[13] = t;

	t = { 532/2, 668/2};
	m_points[14] = t;

	t = { 534/2, 718/2};
	m_points[15] = t;

	return;
}

void LeastSquaresFitting()  
{  
	if (m_nNum<3)  
	{  
		return;  
	}  

	int i=0;  

	int sum_of_x=0; 
	int sum_of_y=0;  
	int sum_of_square_x=0;  
	int sum_of_square_y=0;  
	int sum_of_cube_x=0;  
	int sum_of_cube_y=0;  

	int X1Y1=0;  
	int X1Y2=0;  
	int X2Y1=0;  

	int tmpx;
	int tmpy;

	for (i=0;i<m_nNum;i++)  
	{  
		tmpx = m_points[i].x;
		tmpy = m_points[i].y;
		//x,y坐标和
		sum_of_x = sum_of_x + tmpx;  
		sum_of_y = sum_of_y + tmpy;  

		//sum (x*y)
		X1Y1 = X1Y1 + tmpx * tmpy;  

		//x,y坐标平方和
		tmpx = tmpx * tmpx;
		tmpy = tmpy * tmpy;
		sum_of_square_x = sum_of_square_x + tmpx * tmpx;  
		sum_of_square_y = sum_of_square_y + tmpy * tmpy;  

		//sum (x*y*y)
		X1Y2 = X1Y2 + m_points[i].x * tmpy;  
		//sum (x*x*y)
		X2Y1 = X2Y1 + tmpx * m_points[i].y;  

		//x,y坐标三方和
		sum_of_cube_x = sum_of_cube_x + tmpx * m_points[i].x;  
		sum_of_cube_y = sum_of_cube_y + tmpy * m_points[i].y;

	}  

	double C,D,E,G,H,N;  
	double a,b,c;  
	N = m_nNum;  
	C = N*sum_of_square_x - sum_of_x * sum_of_x;  
	D = N*X1Y1 - sum_of_x*sum_of_y;  
	E = N*sum_of_cube_x + N*X1Y2 - (sum_of_square_x + sum_of_square_y)*sum_of_x;  
	G = N*sum_of_square_y - sum_of_y * sum_of_y;
	H = N*X2Y1 + N*sum_of_cube_y - (sum_of_square_x + sum_of_square_y)*sum_of_y;  
	a = (H*D-E*G)/(C*G-D*D);  
	b = (H*C-E*D)/(D*D-G*C);  
	c = -(a*sum_of_x + b*sum_of_y + sum_of_square_x + sum_of_square_y)/N;  

	double A,B,R;  
	A = a/(-2);  
	B = b/(-2);  
	R = sqrt(a*a+b*b-4*c)/2;  

	double m_fCenterX = A;  
	double m_fCenterY = B;  
	double m_fRadius = R;  

	//R^2 = (x - A)^2 + (y - B)^2
	
	double t;
	int tmp;
	for( int i = 0; i < m_nNum; i++ ){
		t = m_points[i].x;
		cout<<"context.lineTo("<<t<<",";
		
		t = t - A;
		t = R * R - t * t;
		assert( t > -1 );
		t = pow( t ,0.5 );
		cout<<(int)(B - t)<<")"<<endl;
	}


	return;  
}

int main(){
	init();
	LeastSquaresFitting();

	return 0;
}


#define PI 3.1415926

double calcDotMul( double x1,double y1,double x2,double y2 ){
	double ret = x1 * x2 + y1 * y2;
	return ret;
}

double calcAngle( double x1,double y1,double x2,double y2 ){
	double arccos;
	double ret = calcDotMul( x1,y1,x2,y2 );
	double abs1 = pow(pow(x1,2)+pow(y1,2),0.5);
	double abs2 = pow(pow(x2,2)+pow(y2,2),0.5);
	ret /= abs1;
	ret /= abs2;
	
	arccos = acos(ret);

	return (arccos/PI)*180;
}

/*
|i 	j 	k |
|x1	y1	z1|
|x2	y2	z2|
*/
double calcCrossMulDrection2D(double x1,double y1,double x2,double y2 ){
	double z = x1 * y2 - x2 * y1;
	return z;
}

//1 	AC
//0	NOT Rotate	
//-1	CW
#define threshold 60
int judgeRotate( vector<pair<int,int> > dots ){
	int size = dots.size();
	vector<pair<int,int> > vec(size - 1);

	pair<int,int> a;
	pair<int,int> b;
	int direction = 0;
	int totalAngle = 0;
	int angle = 0;
	
	for( int i = 1; i < size; i++ ){
		vec[i - 1] = pair<int,int>( b.first - a.first,b.second - a.second );
	}

	direction = calcCrossMulDrection2D( vec[0].first,vec[0].second,vec[1].first,vec[1].second );
	totalAngle = calcAngle( vec[0].first,vec[0].second,vec[1].first,vec[1].second );

	for( int i = 2; i < vec.size(); i++ ){
		if( calcCrossMulDrection2D( vec[i - 1].first,vec[i - 1].second,vec[i].first,vec[i].second ) != direction ){
			return 0;
		}
		totalAngle += calcAngle( vec[i - 1].first,vec[i - 1].second,vec[i].first,vec[i].second );
	}

	if( totalANgle > threshold ){
		return direction;
	}
	
	return 0;
}
