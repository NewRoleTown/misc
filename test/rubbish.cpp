#include "pch.h"
#include <fstream>
#include <iostream>
#include <assert.h>
#include <cmath>
using namespace std;

struct Matrix1 {
	int row;
	int col;
	double *data;

	Matrix1(int row, int col, double *src) {
		this->row = row;
		this->col = col;
		data = new double[row * col + 1];
		assert(data);
		memcpy(this->data, src, sizeof(double) * row * col);
	}

	void reshape(int newrow, int newcol) {
		assert(row * col == newrow * newcol);
		row = newrow;
		col = newcol;
	}

	void T() {
		reshape(col, row);
	}
};

double zero_double[209];

Matrix1 *Mtrain[209 + 1];
double train_raw[209 + 1][64 * 64 * 3];
double realy[209 + 1];

Matrix1 g_W(209,1, zero_double);
Matrix1 g_dw(209, 1, zero_double);

double g_b = 0.0;
double g_db = 0.0;

double sigmoid(double x) {
	return (double)1.0 / ((double)1.0 + exp(-x));
}

double d_sigmoid(double x) {
	double ret = sigmoid(x);
	return ret * (1 - ret);
}

double calc_Ai_1n( Matrix1 W,Matrix1 x,double b) {
	double ret = b;
	for (int i = 0; i < 64 * 64 * 3; i++) {
		for (int j = 0; j < 64 * 64 * 3; j++) {
			ret += W.data[i] * x.data[j];
		}
	}
	return sigmoid(ret);
}

double calc_L(double y,double a) {
	//np.sum(Y * np.log(A) + (1 - Y) * (np.log(1 - A)))
	double ret = y * log(a) + ((double)1.0 - y) * log(1 - a);
	return -ret;
}

double calc_dLidwj( Matrix1 W,Matrix1 x,int j,int b,double y ) {
	double a = calc_Ai_1n(W, x, b);
	double ret = (a - y) * x.data[j];
	return ret;
}

double calc_dLdwj(Matrix1 W, int j, int b, double y) {
	double ret = 0;
	for (int i = 0; i < 209; i++) {
		ret += calc_dLidwj(W, *Mtrain[i], j, b, realy[i]);
	}
	return ret;
}

void propagate() {

	double db = 0.0;

	for (int i = 0; i < 209; i++) {
		cout << i << endl;
		g_dw.data[i] = calc_dLdwj(g_W, 0.0, g_b, realy[i]);
		cout << i << endl;
		db += ( calc_Ai_1n(g_W, *Mtrain[i], g_b) - realy[i] );
	}

	g_db = db;
}

#define TURNS	1
#define RATE	0.1
void optimize() {
	
	for (int i = 0; i < TURNS; i++) {
		propagate();

		for (int i = 0; i < 209; i++) {
			g_W.data[i] -= RATE * g_dw.data[i];
		}
		g_b -= RATE * g_db;
	}

}

void load_train() {

	ifstream in("./train.txt");
	ifstream yset("./y.txt");

	int i = 0;
	double *p = &train_raw[0][0];
	
	if (yset.is_open())
	{
		while (!yset.eof()) {
			yset >> realy[i++];
		}
		yset.close();
		cout << "load y num: " << i << endl;
	}

	i = 0;
	if (in.is_open())
	{
		while (!in.eof()) {
			in >> p[i++];
			p[i - 1] /= 255;
		}
		in.close();
		cout << "load train num: " << i << endl;
		for (int i = 0; i < 209; i++) {
			Mtrain[i] = new Matrix1(64 * 64 * 3, 1, train_raw[i]);
		}
	}
	
}

int main()
{
	load_train();
	optimize();
}
