#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include <opencv2/core.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>
using namespace std;
#include<windows.h>

int main() {

	return 0;
}


#if 0
int G[24][24];
int tG[24][24];
int mG[24][24];

int tbv = 0;

cv::Mat srcImage;
cv::Mat Img_gray;

int x_base = 7;
int y_base = 5;
int wd = 773;
int hg = 775;

#define zero	0
#define one		1
#define two		2
#define three	3
#define four	4
#define five	5
#define six		6

#define boom	-80

int dr[] = { -1,-1,0,1,1,1,0,-1 };
int dl[] = { 0,1,1,1,0,-1,-1,-1 };

vector<pair<int, int> > vec;
vector<pair<int, int> > zd;
vector<pair<int, int> > control;

void vec_push_new(int ti, int tj) {
	for (int i = 0; i < vec.size(); i++) {
		if (vec[i].first == ti && vec[i].second == tj)
			return;
	}
	vec.push_back(pair<int, int>(ti, tj));
}


void control_push_new(int ti, int tj) {
	for (int i = 0; i < vec.size(); i++) {
		if (control[i].first == ti && control[i].second == tj)
			return;
	}
	control.push_back(pair<int, int>(ti, tj));
}


void trans(int &row, int &col, int y, int x) {
	row = (y - 5) / (775 / 24);
	col = (x - 7) / (773 / 24);
}

int calc_diff(cv::Mat &matSrc1, cv::Mat &matSrc2) {

	cv::Mat matDst1, matDst2;

	cv::resize(matSrc1, matDst1, cv::Size(8, 8), 0, 0, cv::INTER_CUBIC);
	cv::resize(matSrc2, matDst2, cv::Size(8, 8), 0, 0, cv::INTER_CUBIC);

	cv::cvtColor(matDst1, matDst1, CV_BGR2GRAY);
	cv::cvtColor(matDst2, matDst2, CV_BGR2GRAY);

	int iAvg1 = 0, iAvg2 = 0;
	int arr1[64], arr2[64];

	for (int i = 0; i < 8; i++)
	{
		uchar* data1 = matDst1.ptr<uchar>(i);
		uchar* data2 = matDst2.ptr<uchar>(i);

		int tmp = i * 8;

		for (int j = 0; j < 8; j++)
		{
			int tmp1 = tmp + j;

			arr1[tmp1] = data1[j] / 4 * 4;
			arr2[tmp1] = data2[j] / 4 * 4;

			iAvg1 += arr1[tmp1];
			iAvg2 += arr2[tmp1];
		}
	}

	iAvg1 /= 64;
	iAvg2 /= 64;

	for (int i = 0; i < 64; i++)
	{
		arr1[i] = (arr1[i] >= iAvg1) ? 1 : 0;
		arr2[i] = (arr2[i] >= iAvg2) ? 1 : 0;
	}

	int iDiffNum = 0;

	for (int i = 0; i < 64; i++)
		if (arr1[i] != arr2[i])
			++iDiffNum;

	//cout << "iDiffNum = " << iDiffNum << endl;

	if (iDiffNum <= 5)
		return 0;
	else if (iDiffNum > 10)
		return 1;
}
void print() {
	for (int i = 0; i < 24; i++) {
		for (int j = 0; j < 24; j++) {
			if (G[i][j] == boom)
				printf("*", G[i][j]);
			else {
				if (G[i][j] == 0xffffffff)
					printf("9");
				else
					printf("%d", G[i][j]);
			}
		}
		cout << endl;
	}
}

RECT rect;
void rtrans(int row, int col, int &x, int &y) {
	int colsize = (rect.right - 8 - 8) / 24;
	int rowsize = (rect.bottom - 8 - 52) / 24;

	y = row * rowsize + 52 + 4;
	x = col * colsize + 8 + 4;
}

cv::Mat pat1;
cv::Mat pat2;
cv::Mat pat3;
cv::Mat pat4;
cv::Mat pat5;

HWND h;
void one_step() {


	for (int i = 0; i < 24; i++) {
		for (int j = 0; j < 24; j++) {

			int unknown = 0;
			int ui, uj;


			if (zero == G[i][j]) {
				continue;
			}

			if (-1 == G[i][j]) {
				continue;
			}

			if (boom == G[i][j]) {
				continue;
			}

			if (one == G[i][j]) {
				for (int k = 0; k < 8; k++) {
					int ti = i + dr[k];
					int tj = j + dl[k];
					if (ti < 0 || ti >= 24)
						continue;
					if (tj < 0 || tj >= 24)
						continue;

					if (0xffffffff == G[ti][tj]) {
						unknown++;
						ui = ti;
						uj = tj;
					}

				}
				if (1 == unknown) {
					G[ui][uj] = boom;
					zd.push_back(pair<int, int>(ui, uj));

					G[i][j]--;
					control_push_new(i, j);

					for (int m = 0; m < 8; m++) {
						int ti = ui + dr[m];
						int tj = uj + dl[m];

						if (ti < 0 || ti >= 24)
							continue;
						if (tj < 0 || tj >= 24)
							continue;
						if (G[ti][tj] == boom || G[ti][tj] == zero)
							continue;

						if (G[ti][tj] == 0xffffffff) {
							mG[ti][tj]++;
						}
						else {
							G[ti][tj]--;
							if (G[ti][tj] == zero) {
								control_push_new(ti, tj);
							}
						}

					}

				}

			}//ONE
			else {

			}
		}
	}

	for (int t = 0; t < control.size(); t++) {
		int i = control[t].first;
		int j = control[t].second;

		for (int k = 0; k < 8; k++) {
			int ti = i + dr[k];
			int tj = j + dl[k];

			if (ti < 0 || ti >= 24)
				continue;
			if (tj < 0 || tj >= 24)
				continue;
			if (G[ti][tj] == boom)
				continue;

			if (G[ti][tj] == 0xffffffff)
				vec_push_new(ti, tj);
		}
	}

	for (int i = 0; i < control.size(); i++) {
		cout << control[i].first << "," << control[i].second << endl;
	}

	cout << "--------------------------------------------------" << endl;

	if (!vec.size()) {
#if 1
		cout << "ppppppppppppppppppppppppppppppppppppppppppppppppp" << endl;
		HANDLE hP = OpenProcess(PROCESS_ALL_ACCESS, 0, 105508);
		SIZE_T nRead;
		unsigned char bG[32][32];
		int x, y;
		ReadProcessMemory(hP, (LPCVOID)0x1005361, bG, 32 * 32, &nRead);
		if (nRead != 32 * 32) {
			assert(0);
		}
		for (int i = 0; i < 24; i++) {
			for (int j = 0; j < 24; j++) {
				//cout << hex << (int)G[i][j] << endl;
				if (bG[i][j] != 0x8f && G[i][j] == 0xffffffff) {
					rtrans(i, j, x, y);
					PostMessageA(h, WM_LBUTTONDOWN, 0, ((y << 16) | x));
					PostMessageA(h, WM_LBUTTONUP, 0, ((y << 16) | x));
					break;
				}
				Sleep(10);
	}
	}

#endif
	}
	else {

		for (int i = 0; i < vec.size(); i++) {
			cout << vec[i].first << "," << vec[i].second << endl;
			int x, y;
			rtrans(vec[i].first, vec[i].second, x, y);
			cout << "pos = " << x << "," << y << endl;
			PostMessageA(h, WM_LBUTTONDOWN, 0, ((y << 16) | x));
			PostMessageA(h, WM_LBUTTONUP, 0, ((y << 16) | x));
		}
	}

	cout << "--------------------------------------------------" << endl;

	for (int i = 0; i < zd.size(); i++) {
		cout << zd[i].first << "," << zd[i].second << endl;
	}

}





#if 1
static void onChange(int v, void*) {
	if (v != 185)
		return;



	//cvtColor(srcImage, Img_gray, COLOR_BGR2GRAY);
	//pyrUp(Img_gray, Img_gray, Size(srcImage.cols * 2, srcImage.rows * 2));
	cv::Mat kernel = (cv::Mat_<float>(3, 3) << 0, -1, 0, -1, 5, -1, 0, -1, 0);

	cv::Mat gray2;
	filter2D(Img_gray, gray2, -1, kernel);
	threshold(gray2, gray2, v, 255, cv::THRESH_BINARY_INV);

	//pyrUp(Img_gray, Img_gray, Size(srcImage.cols * 2, srcImage.rows * 2));

	cv::Mat element = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3));
	cv::Mat Img_dilate;
	dilate(gray2, Img_dilate, element);
	erode(Img_dilate, Img_dilate, element);

	vector<vector<cv::Point>> contours;
	vector<cv::Vec4i> hierarchy;
	findContours(Img_dilate, contours, hierarchy, cv::RETR_TREE, cv::CHAIN_APPROX_SIMPLE);

	std::cout << contours.size() << endl;


	pyrUp(srcImage, srcImage, cv::Size(srcImage.cols * 2, srcImage.rows * 2));

	std::cout << srcImage.rows << endl;
	std::cout << srcImage.cols << endl;
	
	int count = 0;
	for (int i = 0; i < contours.size(); i++) {
		if (hierarchy[i][3] == 0 && hierarchy[i][2] > 0) {
			auto Round = cv::boundingRect(contours[hierarchy[i][2]]);

			std::cout << "outer = " << contours[hierarchy[i][2]].size() << endl;

			rectangle(srcImage, Round, cv::Scalar(0, 0, 255));


			cv::Mat ImgROI;

			resize(srcImage(Round), ImgROI, cv::Size(20, 20));

			//imwrite("test" + to_string(i) + ".jpg", ImgROI);
			int y = Round.y + Round.height / 2;
			int x = Round.x + Round.width / 2;
			int row, col;
			trans(row, col, y, x);
			if (!calc_diff(pat1,ImgROI)) {
				tG[row][col] = 1;
			}
			else if (!calc_diff(pat2, ImgROI)) {
				tG[row][col] = 2;
			}
			else if (!calc_diff(pat3, ImgROI)) {
				tG[row][col] = 3;
			}
			else if (!calc_diff(pat4, ImgROI)) {
				tG[row][col] = 4;
			}
			else if (!calc_diff(pat5, ImgROI)) {
				tG[row][col] = 5;
			}
			else {
				tG[row][col] = 6;
			}

			count++;
		}
		else if (hierarchy[i][3] == 0) {
			auto Round = cv::boundingRect(contours[i]);

			cv::Mat ImgROI;

			resize(srcImage(Round), ImgROI, cv::Size(20, 20));

			//cout << (int)ImgROI.data[66] << "," << (int)ImgROI.data[67] << "," << (int)ImgROI.data[68] << endl;
			int f = 0;
			if ((int)ImgROI.data[66] == 190) {
				f = 1;
				rectangle(srcImage, Round, cv::Scalar(0, 255, 0));
			}
			else {
				rectangle(srcImage, Round, cv::Scalar(255, 0, 0));
			}
			count++;

			int y = Round.y + Round.height / 2;
			int x = Round.x + Round.width / 2;
			int row, col;
			trans(row, col, y, x);
			if (row < 0 || row >= 24 || col < 0 || col >= 24) {
				std::cout << "errrrrrrrrr" << std::endl;
				cout << Round.y << "," << Round.height << endl;
				cout << Round.x << "," << Round.width << endl;
			}
			else {
				if (f) {
					tG[row][col] = 0;
				}
				else {
					tG[row][col] = 0xffffffff;
				}
				
			}
		}
	}
	//cout << count<<endl;

	/*
	for (int i = 0; i < 24; i++) {
		for (int j = 0; j < 24; j++) {
			cout << G[i][j];
		}
		cout << endl;
	}*/


	vec.clear();
	control.clear();

	zd.clear();
#if 0
	int rebase = 1;
	for (int i = 0; i < 24; i++) {
		for (int j = 0; j < 24; j++) {
			if (tG[i][j] != 0xffffffff) {
				rebase = 0;
			}
		}
	}
#endif
	for (int i = 0; i < 24; i++) {
		for (int j = 0; j < 24; j++) {
			if (G[i][j] == 0xffffffff && tG[i][j] != 0xffffffff) {
				G[i][j] = tG[i][j];
				if (G[i][j] > 0) {
					if (mG[i][j]) {
						G[i][j] -= mG[i][j];
						mG[i][j] = 0;
					}
				}
			}

			if (G[i][j] == zero) {
				control_push_new(i, j);
			}


		}
	}

#if 1
	for (int i = 0; i < contours.size(); i++) {
		if (hierarchy[i][3] == 0 && hierarchy[i][2] > 0) {
			auto Round = cv::boundingRect(contours[hierarchy[i][2]]);
			rectangle(srcImage, Round, cv::Scalar(0, 0, 255),3);
		}
		else if (hierarchy[i][3] == 0) {
			auto Round = cv::boundingRect(contours[i]);
			cv::Mat ImgROI;
			resize(srcImage(Round), ImgROI, cv::Size(20, 20));
			//cout << (int)ImgROI.data[66] << "," << (int)ImgROI.data[67] << "," << (int)ImgROI.data[68] << endl;
			int f = 0;
			if ((int)ImgROI.data[66] == 190) {
				f = 1;
				rectangle(srcImage, Round, cv::Scalar(0, 255, 0),5);
			}
			else {
				rectangle(srcImage, Round, cv::Scalar(255, 0, 0),5);
			}

		}
	}
#endif



	imshow("ori", srcImage);
	cvWaitKey(100);
}
#endif

#if 1


int CaptureImage(HWND hwnd, const CHAR *dirPath, const CHAR *filename)
{
	HDC mdc;
	HBITMAP hbmp;
	CHAR FilePath[MAX_PATH];
	HDC hdcScreen;
	HDC hdcWindow;
	HDC hdcMemDC = NULL;
	HBITMAP hbmScreen = NULL;
	BITMAP bmpScreen;
	RECT rcClient;
	BITMAPFILEHEADER   bmfHeader;
	BITMAPINFOHEADER   bi;
	DWORD dwBmpSize;
	HANDLE hDIB;
	CHAR *lpbitmap;
	HANDLE hFile;
	DWORD dwSizeofDIB;
	DWORD dwBytesWritten;

	//hdcScreen = GetDC(NULL); // 全屏幕DC
	hdcWindow = GetDC(hwnd); // 截图目标窗口DC

	// 创建兼容内存DC
	hdcMemDC = CreateCompatibleDC(hdcWindow);

	if (!hdcMemDC)
	{
		cout << (TEXT("CreateCompatibleDC has failed")) << endl;
		goto done;
	}

	// 获取客户端区域用于计算大小
	GetClientRect(hwnd, &rcClient);

	// 设置延展模式
	//SetStretchBltMode(hdcWindow, HALFTONE);

	// 来源 DC 是整个屏幕而目标 DC 是当前的窗口 (HWND)
	if (!StretchBlt(hdcWindow,
		0, 0,
		rcClient.right, rcClient.bottom,
		hdcWindow,
		0, 0,
		rcClient.right - rcClient.left,
		rcClient.bottom - rcClient.top,
		/*
		GetSystemMetrics(SM_CXSCREEN),
		GetSystemMetrics(SM_CYSCREEN),
		*/
		SRCCOPY))
	{
		cout << (TEXT("StretchBlt has failed")) << endl;
		goto done;
	}

	// 通过窗口DC 创建一个兼容位图
	hbmScreen = CreateCompatibleBitmap(
		hdcWindow,
		rcClient.right - rcClient.left,
		rcClient.bottom - rcClient.top
	);

	if (!hbmScreen)
	{
		cout << (TEXT("CreateCompatibleBitmap Failed")) << endl;
		goto done;
	}

	// 将位图块传送到我们兼容的内存DC中
	SelectObject(hdcMemDC, hbmScreen);





	if (!BitBlt(
		hdcMemDC,   // 目的DC
		0, 0,        // 目的DC的 x,y 坐标
		rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, // 目的 DC 的宽高
		hdcWindow,  // 来源DC
		0, 0,        // 来源DC的 x,y 坐标
		SRCCOPY))   // 粘贴方式
	{
		cout << (TEXT("BitBlt has failed")) << endl;
		goto done;
	}

	// 获取位图信息并存放在 bmpScreen 中
	GetObject(hbmScreen, sizeof(BITMAP), &bmpScreen);

	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = bmpScreen.bmWidth;
	bi.biHeight = bmpScreen.bmHeight;
	bi.biPlanes = 1;
	bi.biBitCount = 32;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrUsed = 0;
	bi.biClrImportant = 0;

	dwBmpSize = ((bmpScreen.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmpScreen.bmHeight;

	// 在 32-bit Windows 系统上, GlobalAlloc 和 LocalAlloc 是由 HeapAlloc 封装来的
	// handle 指向进程默认的堆. 所以开销比 HeapAlloc 要大
	hDIB = GlobalAlloc(GHND, dwBmpSize);
	lpbitmap = (char *)GlobalLock(hDIB);

	// 获取兼容位图的位并且拷贝结果到一个 lpbitmap 中.
	GetDIBits(
		hdcWindow,  // 设备环境句柄
		hbmScreen,  // 位图句柄
		0,          // 指定检索的第一个扫描线
		(UINT)bmpScreen.bmHeight, // 指定检索的扫描线数
		lpbitmap,   // 指向用来检索位图数据的缓冲区的指针
		(BITMAPINFO *)&bi, // 该结构体保存位图的数据格式
		DIB_RGB_COLORS // 颜色表由红、绿、蓝（RGB）三个直接值构成
	);


	sprintf(FilePath, "%s\%s.bmp", dirPath, filename);

	// 创建一个文件来保存文件截图
	hFile = CreateFileA(
		FilePath,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	// 将 图片头(headers)的大小, 加上位图的大小来获得整个文件的大小
	dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// 设置 Offset 偏移至位图的位(bitmap bits)实际开始的地方
	bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER);

	// 文件大小
	bmfHeader.bfSize = dwSizeofDIB;

	// 位图的 bfType 必须是字符串 "BM"
	bmfHeader.bfType = 0x4D42; //BM   

	dwBytesWritten = 0;
	WriteFile(hFile, (LPSTR)&bmfHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL);
	WriteFile(hFile, (LPSTR)&bi, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL);
	WriteFile(hFile, (LPSTR)lpbitmap, dwBmpSize, &dwBytesWritten, NULL);

	// 解锁堆内存并释放
	GlobalUnlock(hDIB);
	GlobalFree(hDIB);

	// 关闭文件句柄
	CloseHandle(hFile);

	// 清理资源
done:
	//DeleteObject(hbmScreen);
	DeleteObject(hdcMemDC);
	//ReleaseDC(NULL, hdcScreen);
	ReleaseDC(hwnd, hdcWindow);

	return 0;
}

int64 CalcImagePerceptualHashKey(cv::InputArray input)
{
	cv::Mat _input = input.getMat();
	cv::Mat pTheImage88 = cv::Mat::zeros(cv::Size(8, 8), _input.channels());
	cv::Mat pGrayscaleImage = cv::Mat::zeros(cv::Size(8, 8), 1);
	//将原图处理成8*8的图片
	resize(input, pTheImage88, cv::Size(8, 8));
	//cvtColor(pTheImage8x8, pGrayscaleImage);
	cvtColor(pTheImage88, pGrayscaleImage, cv::COLOR_RGB2GRAY);
	pTheImage88.release();

	//计算平均值
	float ElementMean = 0;
	for (size_t y = 0; y < 8; y++)
	{
		for (size_t x = 0; x < 8; x++)
		{
			unsigned char elemet = pGrayscaleImage.at<unsigned char>(x, y);
			ElementMean += elemet;
		}
	}
	ElementMean = ElementMean / 64;
	//得到hash值
	int64 HashKey = 0;

	for (size_t y = 0; y < 8; y++)
	{
		for (size_t x = 0; x < 8; x++)
		{
			unsigned char elemet = pGrayscaleImage.at<unsigned char>(x, y);
			if (elemet > ElementMean)
			{
				//向左移一位
				HashKey <<= 1;
			}
			else
			{
				//向左移一位
				HashKey <<= 1;
				//最后一位复制为1
				HashKey |= 1;//相当于HashKey =HashKey | 1
			}
		}
	}
	return HashKey;
}

float CompareImageSimilarity(int64 key1, int64 key2)
{
	//两组hash码对比
	int64 result = key1 ^ key2;
	int count = 0;
	int i = 64;
	while (i--)
	{
		//判断最后一位是否为1，即是否相同
		if ((result & 1) == 1)
			count++;
		//右移一位，进入下一位
		result >>= 1;
	}
	return count == 0 ? 1 : (64 - count) / (float)64;
}




int main() {

	memset(G, 0xffffffff, sizeof(G));
	memcpy(tG, G, sizeof(G));

	pat1 = cv::imread("C:\\Users\\Lenovo\\Desktop\\1.jpg");
	pat2 = cv::imread("C:\\Users\\Lenovo\\Desktop\\2.jpg");
	pat3 = cv::imread("C:\\Users\\Lenovo\\Desktop\\3.jpg");
	pat4 = cv::imread("C:\\Users\\Lenovo\\Desktop\\4.jpg");
	pat5 = cv::imread("C:\\Users\\Lenovo\\Desktop\\5.jpg");
#if 1
	h = FindWindowA(NULL, "扫雷");
	if (!h || h == INVALID_HANDLE_VALUE) {
		return 0;
	}
	cout << "Find Window" << endl;
	GetClientRect(h, &rect);
	cout << "right = " << rect.right << endl;
	cout << "bottom = " << rect.bottom << endl;

	while (1) {
	CaptureImage(h, "C:\\Users\\Lenovo\\Desktop\\", "win");
#if 1
	srcImage = cv::imread("C:\\Users\\Lenovo\\Desktop\\win.bmp");

	//判断图像是否读取成功
	if (srcImage.empty())
	{
		cout << "图像加载失败!" << endl;
		return -1;
	}
	else {
		cout << "图像加载成功!" << endl << endl;
	}

	//RECT orr = {100,100,100,100};
	cout << srcImage.cols << endl;
	srcImage = srcImage(cv::Rect(8, 52,srcImage.cols  - 8, srcImage.rows  - 52));

	cvtColor(srcImage, Img_gray, cv::COLOR_BGR2GRAY);
	
	for (int i = 0; i < Img_gray.rows; i++) {
		for (int j = 0; j < Img_gray.cols; j++) {
			unsigned char c = Img_gray.data[i * Img_gray.cols + j];
			if ((int)c > 220) {
				Img_gray.data[i * Img_gray.cols + j] = 150;
			}
		}
	}

	pyrUp(Img_gray, Img_gray, cv::Size(srcImage.cols * 2, srcImage.rows * 2));

	cv::namedWindow("ori", cv::WINDOW_AUTOSIZE);
	//cv::createTrackbar("tb", "ori", &tbv, 255, onChange);

	//cv::line(Img_gray, cv::Point(0, 0),cv::Point(780,5),cv::Scalar(255,255,0));
	//imshow("ori", Img_gray);

	
		onChange(185, NULL);
		print();
		
		one_step();
		//Sleep(100);
	}
	cvvWaitKey(0);
#endif
#endif
}
#endif

#if 0
int main() {

	srcImage = imread("C:\\Users\\Lenovo\\Desktop\\win.png");

	//判断图像是否读取成功
	if (srcImage.empty())
	{
		cout << "图像加载失败!" << endl;
		return -1;
	}
	else {
		cout << "图像加载成功!" << endl << endl;
	}

	//pyrUp(srcImage, srcImage, Size(srcImage.cols * 2, srcImage.rows * 2));

	
	cvtColor(srcImage, Img_gray, COLOR_BGR2GRAY);

	for (int i = 0; i < Img_gray.rows; i++) {
		for (int j = 0; j < Img_gray.cols; j++) {
			unsigned char c = Img_gray.data[i * Img_gray.cols + j];
			if ((int)c > 220 ) {
				Img_gray.data[i * Img_gray.cols + j] = 150;
			}
		}
	}

	pyrUp(Img_gray, Img_gray, Size(srcImage.cols * 2, srcImage.rows * 2));



	namedWindow("ori", WINDOW_AUTOSIZE);
	createTrackbar("tb", "ori", &tbv, 255, onChange );

	imshow("ori", Img_gray);
	waitKey(0);
	/*
	


	threshold(Img_gray, Img_gray, 170, 255, THRESH_BINARY_INV);


	dilate(Img_dilate, Img_dilate, element);
	//erode(Img_dilate, Img_dilate, element);


	
	imshow("ori", Img_gray);

	
	*/

	return 0;
}

#endif











#if 0
int main()
{
	Mat srcImage;
	srcImage = imread("C:\\Users\\Lenovo\\Desktop\\sd.jpg");

	//判断图像是否读取成功
	if (srcImage.empty())
	{
		cout << "图像加载失败!" << endl;
		return -1;
	}
	else
		cout << "图像加载成功!" << endl << endl;

	Mat Img_gray;
	cvtColor(srcImage, Img_gray, COLOR_BGR2GRAY);

	Mat kernel = (Mat_<float>(3, 3) << 0, -1, 0, -1, 5, -1, 0, -1, 0);
	filter2D(Img_gray, Img_gray, -1, kernel);
	threshold(Img_gray, Img_gray, 150, 255, THRESH_BINARY_INV);

	Mat element = getStructuringElement(MORPH_RECT, Size(3, 3));
	Mat Img_dilate;
	dilate(Img_gray, Img_dilate,element);
	dilate(Img_dilate, Img_dilate, element);

	vector<vector<Point>> contours;
	vector<Vec4i> hierarchy;
	findContours(Img_dilate, contours, hierarchy, RETR_TREE, CHAIN_APPROX_SIMPLE);

	//cout << "共检测到轮廓的个数\t" << contours.size() << endl;

	int count = 0;
	for (int i = 0; i < contours.size(); i++) {
		if (hierarchy[i][3] == 0 && hierarchy[i][2] > 0 ) {
			auto Round = boundingRect(contours[hierarchy[i][2]]);
			
			cout << "outer = " << contours[hierarchy[i][2]].size() << endl;

			Mat ImgROI;

			resize(srcImage(Round), ImgROI, Size(20, 20));
			imwrite("test" + to_string(i) + ".jpg", ImgROI);

			rectangle(srcImage, Round, Scalar(0, 0, 255));

		}
	}
	
	auto Round = boundingRect(contours[0]);     //外边缘

	/*cout << "宽度\t" << Round.width << endl;
	cout << "高度\t" << Round.height << endl;*/

	rectangle(srcImage, Round, Scalar(255, 0, 0));

	
	namedWindow("ori", WINDOW_AUTOSIZE);
	imshow("ori", srcImage);


	waitKey(0);
	return 0;
}
#endif

#if 0
using namespace cv;
int main()
{
	Mat srcImage;
	srcImage = imread("C:\\Users\\Lenovo\\Desktop\\sd.jpg");

	//判断图像是否读取成功
	if (srcImage.empty())
	{
		cout << "图像加载失败!" << endl;
		return -1;
	}
	else
		cout << "图像加载成功!" << endl << endl;

	//分割成三通道图像
	vector<Mat> channels;
	split(srcImage, channels);
	
	//设定bin数目
	int histBinNum = 255;

	//设定取值范围
	float range[] = { 0, 255 };
	const float* histRange = { range };

	bool uniform = true;
	bool accumulate = false;

	//声明三个通道的hist数组
	Mat red_hist, green_hist, blue_hist;

	//计算直方图
	calcHist(&channels[0], 1, 0, Mat(), red_hist, 1, &histBinNum, &histRange, uniform, accumulate);
	calcHist(&channels[1], 1, 0, Mat(), green_hist, 1, &histBinNum, &histRange, uniform, accumulate);
	calcHist(&channels[2], 1, 0, Mat(), blue_hist, 1, &histBinNum, &histRange, uniform, accumulate);

	//创建直方图窗口
	int hist_w = 200;
	int hist_h = 200;
	int bin_w = cvRound((double)srcImage.cols / histBinNum);

	Mat histImage(srcImage.cols, srcImage.rows, CV_8UC3, Scalar(0, 0, 0));

	//将直方图归一化到范围[0, histImage.rows]
	normalize(red_hist, red_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
	normalize(green_hist, green_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
	normalize(blue_hist, blue_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());

	//循环绘制直方图
	for (int i = 1; i < histBinNum; i++)
	{
		line(histImage, 
			Point(bin_w*(i - 1), srcImage.rows - cvRound(red_hist.at<float>(i - 1))),
			Point(bin_w*(i),     srcImage.rows - cvRound(red_hist.at<float>(i))), 
			Scalar(0, 0, 255), 1, 8, 0);
		line(histImage, Point(bin_w*(i - 1), srcImage.rows - cvRound(green_hist.at<float>(i - 1))),
			Point(bin_w*(i), srcImage.rows - cvRound(green_hist.at<float>(i))), 
			Scalar(0, 255, 0), 1, 8, 0);
		line(histImage, Point(bin_w*(i - 1), srcImage.rows - cvRound(blue_hist.at<float>(i - 1))),
			Point(bin_w*(i), srcImage.rows - cvRound(blue_hist.at<float>(i))), 
			Scalar(255, 0, 0), 1, 8, 0);
	}

	line(histImage, Point(0, 0), Point(0, 20), Scalar(0, 0, 255), 1, 8, 0);
	//namedWindow("原图像", WINDOW_AUTOSIZE);
	//imshow("原图像", srcImage);

	namedWindow("图像直方图", WINDOW_AUTOSIZE);
	imshow("图像直方图", histImage);

	waitKey(0);

	return 0;
}
#endif

#if 0

#define M  6
#define N  9

int image[M][N] = {
	{0,0,0,0,0,0,0,0,0},
	{0,1,1,1,1,1,1,1,0},
	{0,1,0,0,1,0,0,1,0},
	{0,1,0,0,1,0,0,1,0},
	{0,1,1,1,1,1,1,1,0},
	{0,0,0,0,0,0,0,0,0}
};
int res[M][N];

int dr_s[] = { 0,-1,-1,-1,0,1,1,1 };
int dl_s[] = { -1,-1,0,1,1,1,0,-1 };

int dr_n[] = { 0,1,1,1,0,-1,-1,-1 };
int dl_n[] = { -1,-1,0,1,1,1,0,-1 };

void solve() {
	int i = 1, j = 1;
	int i1 = -1, j1 = -1;
	int i2 = -1, j2 = -1;
	int i3 = -1, j3 = -1;
	int i4 = -1, j4 = -1;
	int NBD = 1;

	int start;

	while ( i < M && j < N ) {
		i1 = -1;
		j1 = -1;

		if (image[i][j] == 1 && !image[i][j - 1]) {
			i2 = i;
			j2 = j - 1;
			NBD++;

			start = 0;
		}
		else if (image[i][j] >= 1 && !image[i][j + 1]) {
			i2 = i;
			j2 = j + 1;

			start = 4;
		}
		else {
#if 0
			call 0xFFFFFFFFFFFFEF38
			and eax, 0xFF00FF00
#endif
		}

		int cnt;
		for (cnt = 0; cnt < 8; cnt++) {
			int ti = i2 + dr_s[(start + cnt) % 8];
			int tj = j2 + dl_s[(start + cnt) % 8];

			if( image[ti][tj] ){
				i1 = ti;
				j1 = tj;
				break;
			}
		}

		if (cnt == 8) {
			image[i][j] = -NBD;
			goto step9;
		}

		i2 = i1;
		j2 = j1;
		i3 = i;
		j3 = j;

		retry:

		if (i2 == i3) {
			if (j2 == j3 - 1) {
				start = 0;
			}
			else if (j2 == j3 + 1) {
				start = 4;
			}
		}
		else if (i2 == i3 - 1) {
			if (j2 == j3) {
				start = 2;
			}
			else if (j2 == j3 - 1) {
				start = 1;
			}
			else if(j2 == j3 + 1){
				start = 3;
			}
		}
		else if( i2 == i3 + 1){
			if (j2 == j3) {
				start = 6;
			}
			else if (j2 == j3 - 1) {
				start = 7;
			}
			else if (j2 == j3 + 1) {
				start = 5;
			}
		}

		//start = (start + cnt) % 8;
		for (cnt = 0; cnt < 8; cnt++) {
			int ti = i2 + dr_n[(start + cnt) % 8];
			int tj = j2 + dl_n[(start + cnt) % 8];

			if (image[ti][tj]) {
				i4 = ti;
				j4 = tj;
				break;
			}
		}

		assert(cnt < 8);

		if (!image[i3][j3 + 1]) {
			image[i3][j3] = -NBD;
		}
		else if (1 == image[i3][j3]) {
			image[i3][j3] = -NBD;
		}
		else {
			i2 = i3;
			i3 = i4;

			j2 = j3;
			j3 = j4;

			goto retry;
		}

		if (i4 == i && j4 == j && i3 == i1 && j3 == j1) {
			goto step9;
		}

	step9:

		if (image[i][j] != 1) {
			NBD = image[i][j] > 0?image[i][j]:-image[i][j];
		}

		j++;
		if (j == N) {
			i++;
			j = 0;
		}
	}
}

int main() {

	return 0;
}

#endif
#endif
#if 0
class State {

public:
	//These represents the actual x and actual y
	float x;
	float y;
	float theta;

	//These represents the grid x and grid y  
	int gx;
	int gy;

	float cost2d;
	float cost3d;

	float velocity;
	float steer_angle;

	State* parent;
	State* next;

	State(float X, float Y, float THETA)
	{
		x = X;
		y = Y;
		gx = x * 10;
		gy = y * 10;
		theta = THETA;
		parent = NULL;
		cost2d = 0;
	}

	State()
	{
		x = 0;
		y = 0;
		theta = 0;
		parent = NULL;
		cost2d = 0;
	}
};

cv::RNG rng(12345);

class Vehicle {

public:

	float BOT_L = 2.5;
	float BOT_W = 1.5;
	float BOT_MAX_ALPHA = 30;
	vector<State> nextStates(State*);
};
#define PI 3.1415926
vector <State> Vehicle::nextStates(State* n)//vector<Vehicle::State>
{
	vector<State> next;
	State t;
	float alpha, beta, r, d = 1;
	//alpha=steering angle, beta = turning angle, r=turning radius, d= distanced travelled

	for (alpha = -BOT_MAX_ALPHA; alpha <= BOT_MAX_ALPHA + 0.01; alpha += BOT_MAX_ALPHA)
	{
		beta = abs(d*tan(alpha*PI / 180) / BOT_L);
		if (abs(beta) > 0.001)
		{
			r = abs(BOT_L / tan(alpha*PI / 180));
			if (alpha < 0)
			{
				t.x = n->x + sin(n->theta)*r - sin(n->theta - beta)*r;
				t.y = n->y - cos(n->theta)*r + cos(n->theta - beta)*r;
				t.theta = fmod(n->theta + beta, 2 * PI);
			}
			else
			{
				t.x = n->x - sin(n->theta)*r + sin(n->theta + beta)*r;
				t.y = n->y + cos(n->theta)*r - cos(n->theta + beta)*r;
				t.theta = fmod(n->theta - beta, 2 * PI);
			}

			if (t.theta < 0)
				t.theta += 2 * PI;
		}
		else
		{
			t.x = n->x + d * cos(n->theta);
			// if turning radius is very small we assume that the back tire has moved straight
			t.y = n->y + d * sin(n->theta);
			t.theta = n->theta;
		}
		t.gx = (int)(t.y * 10);
		t.gy = (int)(t.x * 10);
		t.steer_angle = alpha;

		if (t.gx >= 0 && t.gx < 1000 && t.gy >= 0 && t.gy < 1000)//change upperbound according to the map size
		{
			next.push_back(t);
		}
	}
	return next;
}

class GUI {
public:
	int rows;
	int cols;
	cv::Mat display;

	GUI(int rows, int cols);
	void draw_obstacles(bool** obs_map);
	void draw_car(State src, Vehicle car);
	void show();
	void show(int t);
};

GUI::GUI(int rows, int cols) {
	this->rows = rows;
	this->cols = cols;
	display = cv::Mat(cv::Size(rows, cols), CV_8UC3, cv::Scalar(220, 220, 220));
}

void GUI::draw_obstacles(bool** obs_map) {
	for (int i = 0; i < cols; i++)
		for (int j = 0; j < rows; j++)
			if (obs_map[i][j])
				display.at<cv::Vec3b>(rows - j, i) = { 128, 128, 128 };

	return;
}

void GUI::draw_car(State state, Vehicle car) {
	cv::RotatedRect rotRect = cv::RotatedRect(cv::Point2f(state.x * 10, 1000 - state.y * 10), cv::Size2f(car.BOT_L * 10, car.BOT_W * 10), -state.theta * 180 / 3.14);
	cv::Point2f vert[4];
	rotRect.points(vert);
	for (int i = 0; i < 4; i++)
		line(display, vert[i], vert[(i + 1) % 4], cv::Scalar(200, 0, 0));

	return;
}

void GUI::show() {
	imshow("Display", display);
	cv::waitKey(0);
	return;
}

void GUI::show(int t) {
	imshow("Display", display);
	cv::waitKey(t);
	return;
}

class Map {
public:

	State end;
	bool** obs_map;
	int** acc_obs_map;
	float map_resolution;
	vector< vector<cv::Point> > obs;

	int MAP_THETA = 72;
	int MAPX = 1000;
	int MAPY = 1000;
	int VISX = 100;
	int VISY = 100;

	Vehicle car;

	Map()
	{

	}
	Map(bool**, State, vector<vector<cv::Point>>);
	bool helperSAT(vector <cv::Point> v1, vector <cv::Point> v2);
	void initCollisionChecker();
	bool checkCollision(State pos);
	bool isReached(State curr);
	bool checkCollisionSat(State pos);

};

Map::Map(bool **obs_map, State end, vector<vector<cv::Point>> obs) {
	this->obs = obs;
	this->obs_map = obs_map;
	this->end = end;
	this->map_resolution = 10;
	initCollisionChecker();
}

bool Map::isReached(State current) {

	/* In this we could have int in place of bool which tells distance between them so
	thst we could act accordingly && fabs(Curr.theta-End.theta)<5*/
	//
	if (abs(current.x - end.x) < 1 && abs(current.y - end.y) < 1 && (abs(current.theta - end.theta) < 3.14 / 9 || abs(current.theta - 72 + end.theta) < 3.14 / 9))
		return true;
	else return false;
}

void Map::initCollisionChecker() {
	acc_obs_map = new int*[MAPX];
	for (int i = 0; i < MAPX; i++)
	{
		acc_obs_map[i] = new int[MAPY];
		for (int j = 0; j < MAPY; j++) {
			acc_obs_map[i][j] = obs_map[i][j];

		}
	}

	for (int i = 0; i < MAPX; i++)
		for (int j = 1; j < MAPY; j++) {
			acc_obs_map[i][j] = acc_obs_map[i][j - 1] + acc_obs_map[i][j];

		}

	for (int j = 0; j < MAPY; j++)
		for (int i = 1; i < MAPX; i++) {
			acc_obs_map[i][j] = acc_obs_map[i - 1][j] + acc_obs_map[i][j];

		}

	return;
}

bool Map::checkCollision(State pos) {

	if (pos.x*map_resolution >= MAPX || pos.x*map_resolution < 0 || pos.y*map_resolution >= MAPY || pos.y*map_resolution < 0)
		return true;

	//first use a bounding box around car to check for collision in O(1) time
	int max_x, min_x, max_y, min_y;
	max_x = map_resolution * (pos.x + car.BOT_L*abs(cos(pos.theta)) / 2 + car.BOT_W*abs(sin(pos.theta)) / 2) + 1;
	min_x = map_resolution * (pos.x - car.BOT_L*abs(cos(pos.theta)) / 2 - car.BOT_W*abs(sin(pos.theta)) / 2) - 1;

	max_y = map_resolution * (pos.y + car.BOT_L*abs(sin(pos.theta)) / 2 + car.BOT_W*abs(cos(pos.theta)) / 2) + 1;
	min_y = map_resolution * (pos.y - car.BOT_L*abs(sin(pos.theta)) / 2 - car.BOT_W*abs(cos(pos.theta)) / 2) - 1;

	if (max_x >= MAPX || min_x < 0 || max_y >= MAPY || min_y < 0)
		return true;

	if (acc_obs_map[max_x][max_y] + acc_obs_map[min_x][min_y] == acc_obs_map[max_x][min_y] + acc_obs_map[min_x][max_y]) {
		return false;
	}

	// brute force check through the car
	for (float i = -car.BOT_L / 2.0; i <= car.BOT_L / 2.0 + 0.001; i += 0.25)
		for (float j = -car.BOT_W / 2.0; j <= car.BOT_W / 2.0 + 0.001; j += 0.25)
		{
			int s = map_resolution * (pos.x + i * cos(pos.theta) + j * sin(pos.theta)) + 0.001;
			int t = map_resolution * (pos.y + i * sin(pos.theta) + j * cos(pos.theta)) + 0.001;

			if (obs_map[s][t])
				return true;
		}
	return false;

}
bool Map::helperSAT(vector <cv::Point> v1, vector <cv::Point> v2)
{
	// cout<<"Inside SAT"<<endl;
	for (int i = 0; i < v1.size(); ++i)
	{
		// cout<<v1[i]<<endl;
	}
	// cout<<v1.size()<<" "<<v2.size()<<endl;
	// int t;
	// cin >>t;

	double slope;
	double theta;
	double dis;
	double rmin1, rmax1, rmin2, rmax2;
	rmin1 = INT_MAX;
	rmin2 = INT_MAX;
	rmax1 = INT_MIN;
	rmax2 = INT_MIN;
	bool collide = false;
	for (int i = 0; i < v1.size() - 1; i++)
	{
		if ((v1[i + 1].x == v1[i].x)) slope = INT_MAX;
		else slope = (v1[i + 1].y - v1[i].y) / (v1[i + 1].x - v1[i].x);

		if (slope == 0) slope = INT_MAX;
		else slope = -1 * (1 / slope);

		// cout<<"1"<<endl;
		int count = 0;
		for (int j = 0; j < v1.size(); j++)
		{
			// cout<<"D"<<endl;
			// cout<<slope<<endl;
			// // cout<<atan((v1[j].y)/(v1[j].x))<<endl;
			if (v1[j].x == 0) theta = CV_PI / 2 - slope;
			else theta = atan((v1[j].y) / (v1[j].x)) - slope;
			// cout<<"D"<<endl;
			dis = sqrt(v1[j].y*v1[j].y + v1[j].x*v1[j].x);
			// cout<<"D"<<endl;
			rmin1 = min(rmin1, dis*cos(theta));
			// cout<<"D"<<endl;
			rmax1 = max(rmax1, dis*cos(theta));
		}
		// cout<<"1"<<endl;
		for (int j = 0; j < v2.size(); j++)
		{
			if (v2[j].x == 0) theta = CV_PI / 2 - slope;
			else theta = atan((v2[j].y) / (v2[j].x)) - slope;
			dis = sqrt(v2[j].y*v2[j].y + v2[j].x*v2[j].x);
			rmin2 = min(rmin2, dis*cos(theta));
			rmax2 = max(rmax2, dis*cos(theta));
		}
		if (rmin2 >= rmin1 && rmax2 <= rmax1)
			collide = true;
		else if (rmin1 >= rmin2 && rmax1 <= rmax2)
			collide = true;
		if (!collide)
		{
			// cout<<"Returned"<<endl;
			return false;
		}
		// we assume the line passes through origin and the slope is -1/slope
	}

	// cout<<"After Loop1 "<<endl;
	// int t;
	// cin >>t;

	for (int i = 0; i < v2.size() - 1; i++)
	{

		if ((v1[i + 1].x == v1[i].x)) slope = INT_MAX;
		else slope = (v1[i + 1].y - v1[i].y) / (v1[i + 1].x - v1[i].x);

		if (slope == 0) slope = INT_MAX;
		else slope = -1 * (1 / slope);

		for (int j = 0; j < v1.size(); j++)
		{
			if (v1[j].x == 0) theta = CV_PI / 2 - slope;
			else theta = atan((v1[j].y) / (v1[j].x)) - slope;
			dis = sqrt(v1[j].y*v1[j].y + v1[j].x*v1[j].x);
			rmin1 = min(rmin1, dis*cos(theta));
			rmax1 = max(rmax1, dis*cos(theta));
		}
		for (int j = 0; j < v2.size(); j++)
		{
			if (v2[j].x == 0) theta = CV_PI / 2 - slope;
			else theta = atan((v2[j].y) / (v2[j].x)) - slope;
			dis = sqrt(v2[j].y*v2[j].y + v2[j].x*v2[j].x);
			rmin2 = min(rmin2, dis*cos(theta));
			rmax2 = max(rmax2, dis*cos(theta));
		}
		if (rmin2 >= rmin1 && rmax2 <= rmax1)
			collide = true;
		else if (rmin1 >= rmin2 && rmax1 <= rmax2)
			collide = true;
		if (!collide)
			return false;
		// we assume the line passes through origin and the slope is -1/slope
	}
	return true;
}

bool Map::checkCollisionSat(State pos)
{
	bool collide = false;
	vector<cv::Point> v1;

	cv::Point p1;
	p1.x = map_resolution * (pos.x - car.BOT_L*abs(cos(pos.theta)) / 2 - car.BOT_W*abs(sin(pos.theta)) / 2);
	p1.y = map_resolution * (pos.y - car.BOT_L*abs(sin(pos.theta)) / 2 + car.BOT_W*abs(cos(pos.theta)) / 2);
	v1.push_back(p1);

	cv::Point p2;
	p2.x = map_resolution * (pos.x - car.BOT_L*abs(cos(pos.theta)) / 2 - car.BOT_W*abs(sin(pos.theta)) / 2);
	p2.y = map_resolution * (pos.y + car.BOT_L*abs(sin(pos.theta)) / 2 + car.BOT_W*abs(cos(pos.theta)) / 2);
	v1.push_back(p2);

	cv::Point p3;
	p3.x = map_resolution * (pos.x + car.BOT_L*abs(cos(pos.theta)) / 2 + car.BOT_W*abs(sin(pos.theta)) / 2);
	p3.y = map_resolution * (pos.y + car.BOT_L*abs(sin(pos.theta)) / 2 - car.BOT_W*abs(cos(pos.theta)) / 2);
	v1.push_back(p3);

	cv::Point p4;
	p4.x = map_resolution * (pos.x + car.BOT_L*abs(cos(pos.theta)) / 2 + car.BOT_W*abs(sin(pos.theta)) / 2);
	p4.y = map_resolution * (pos.y - car.BOT_L*abs(sin(pos.theta)) / 2 - car.BOT_W*abs(cos(pos.theta)) / 2);
	v1.push_back(p4);

	for (int i = 0; i < obs.size(); ++i)
	{
		if (helperSAT(v1, obs[i]))
			return true;
	}
	return false;
}

#define DX 250
#define DY 250
class Heuristic
{
public:
	typedef struct
	{
		int x, y;
		float dis;
	}smallestcost_2d;

	Heuristic() {}
	smallestcost_2d** h_vals;
	State target;
	void Dijkstra(Map map, State target);
};

class compareHeuristic {
public:
	bool operator ()(Heuristic::smallestcost_2d a, Heuristic::smallestcost_2d b)
	{
		return (a.dis > b.dis);
	}
};


bool isvalid(Heuristic::smallestcost_2d neighbor)
{
	if (neighbor.x < 0 || neighbor.y < 0 || neighbor.x >= DX || neighbor.y >= DY)
		return false;
	return true;
}


float distance(Heuristic::smallestcost_2d source, Heuristic::smallestcost_2d neighbor)
{
	return (sqrt((source.x - neighbor.x)*(source.x - neighbor.x) + (source.y - neighbor.y)*(source.y - neighbor.y)));
}

#include<queue>
void Heuristic::Dijkstra(Map map, State target)
{
	priority_queue <smallestcost_2d, vector<smallestcost_2d>, compareHeuristic> pq;

	int** grid_map = new int*[DX];
	for (int i = 0; i < DX; i++)
	{
		grid_map[i] = new int[DY];
	}

	for (int i = 0; i < map.MAPX; i++)
	{
		for (int j = 0; j < map.MAPY; j++)
		{
			if (map.obs_map[i][j])
				grid_map[i*DX / map.MAPX][j*DY / map.MAPY] = 1;
		}
	}

	h_vals = new smallestcost_2d*[DX];
	for (int i = 0; i < DX; i++)
	{
		h_vals[i] = new smallestcost_2d[DY];
		for (int j = 0; j < DY; j++)
			h_vals[i][j].dis = FLT_MAX;
	}

	bool **is_visited = new bool*[DX];
	for (int i = 0; i < DX; i++)
	{
		is_visited[i] = new bool[DY];
		for (int j = 0; j < DY; j++)
		{
			is_visited[i][j] = false;
		}
	}

	is_visited[target.gx*DX / map.MAPX][target.gy*DY / map.MAPY] = true;

	h_vals[target.gx*DX / map.MAPX][target.gy*DY / map.MAPY].dis = 0;
	h_vals[target.gx*DX / map.MAPX][target.gy*DY / map.MAPY].x = target.gx*DX / map.MAPX;
	h_vals[target.gx*DX / map.MAPX][target.gy*DY / map.MAPY].y = target.gy*DY / map.MAPY;
	pq.push(h_vals[target.gx*DX / map.MAPX][target.gy*DY / map.MAPY]);


	while (pq.size() > 0)
	{
		smallestcost_2d temp;
		temp = pq.top();
		pq.pop();
		is_visited[temp.x][temp.y] = true;

		for (int i = temp.x - 1; i <= temp.x + 1; i++)
		{
			for (int j = temp.y - 1; j <= temp.y + 1; j++)
			{
				smallestcost_2d neighbor;
				neighbor.x = i;
				neighbor.y = j;

				if (!isvalid(neighbor)) continue;
				if (grid_map[i][j] != 1 && is_visited[i][j] == false)
				{
					if (h_vals[i][j].dis > h_vals[temp.x][temp.y].dis + distance(temp, neighbor))
					{
						h_vals[i][j].dis = h_vals[temp.x][temp.y].dis + distance(temp, neighbor);
						h_vals[i][j].x = i;
						h_vals[i][j].y = j;
						pq.push(h_vals[i][j]);
					}
				}
			}
		}
	}


}

class Planner
{
public:
	Planner() {}
	Heuristic h_obj;
	bool operator()(State a, State b);
	vector<State> path;
	vector<State> plan(State, State, bool**, Vehicle, vector<vector<cv::Point>>);
};

double** H;
bool Planner::operator()(State a, State b)
{
	// cout<<"X "<<a.gx<<" Y "<<a.gy<<" Cost "<<H[a.gx][a.gy]<<endl;
	// cout<<"X "<<b.gx<<" Y "<<b.gy<<" Cost "<<H[b.gx][b.gy]<<endl;
	return (a.cost2d + H[a.gx][a.gy] / 10 > b.cost2d + H[b.gx][b.gy] / 10);
}

double dis(State a, State* b)
{
	return (sqrt((b->gx - a.gx)*(b->gx - a.gx) + (b->gy - a.gy)*(b->gy - a.gy)));
}

//vector<State> path = astar.plan(start, target, obs_map, car ,obs);
vector<State> Planner::plan(State start, State end, bool** obs_map, Vehicle car, vector<vector<cv::Point>> obs)
{

	Map map(obs_map, end, obs);                          //object of Map class

	map.initCollisionChecker();


	State star(25, 90, 0);

	cout << "SAT : " << map.checkCollisionSat(start) << endl;;
	cout << "SAT : " << map.checkCollisionSat(end) << endl;;

	// int t;
	// cin >>t;

	h_obj.Dijkstra(map, end);

	H = new double*[map.MAPX];
	for (int i = 0; i < map.MAPX; i++)
	{
		H[i] = new double[map.MAPY];
		for (int j = 0; j < map.MAPY; j++)
			H[i][j] = h_obj.h_vals[i*DX / map.MAPX][j*DY / map.MAPY].dis;
	}


	State*** visited_state = new State**[100];
	for (int i = 0; i < 100; i++)
	{
		visited_state[i] = new State*[100];
		for (int j = 0; j < 100; j++)
			visited_state[i][j] = new State[72];
	}

	//To mark the visited states MAPX, MAPY and MAP_THETA are to be imported from the Map class
	bool*** visited = new bool**[map.VISX];
	for (int i = 0; i < map.VISX; i++)
	{
		visited[i] = new bool*[map.VISY];
		for (int j = 0; j < map.VISY; j++)
		{
			visited[i][j] = new bool[map.MAP_THETA];
			for (int k = 0; k < 72; k++)
			{
				visited[i][j][k] = false;
			}
		}
	}

	priority_queue <State, vector<State>, Planner> pq;
	pq.push(start);

	double checkCollisionTime = 0;
	double nextStatesTime = 0;

	while (!pq.empty())
	{
		State current = pq.top();
		pq.pop();
		int grid_theta = ((int)(current.theta * 180 / (PI * 5))) % 72; //grid_theta varies from 0-71 

		if (visited[(int)current.x][(int)current.y][grid_theta])
			continue;

		visited[(int)current.x][(int)current.y][grid_theta] = true;
		visited_state[(int)current.x][(int)current.y][grid_theta] = current;

		if (map.isReached(current))                     //checks if it has reached the goal
		{
			cout << "Time :CollisionChecker= " << checkCollisionTime << endl;
			cout << "Time :nextStates= " << nextStatesTime << endl;
			cout << "REACHED!" << endl;

			State temp = current;
			while (temp.parent != NULL)
			{
				path.push_back(temp);
				temp = *(temp.parent);
			}
			reverse(path.begin(), path.end());
			return path;
		}


		vector<State> next = car.nextStates(&current);


		for (vector<State>::iterator it = next.begin(); it != next.end(); it++)
		{
			State nextS = *it;
			int next_theta = ((int)(nextS.theta * 180 / (PI * 5))) % 72;

			if (visited[(int)nextS.x][(int)nextS.y][next_theta])
				continue;



			if (!map.checkCollisionSat(nextS))
			{
				it->parent = &(visited_state[(int)current.x][(int)current.y][grid_theta]);
				it->cost2d = current.cost2d + 1;
				pq.push(*it);
			}

			//cout<<" time: "<<double(time_end-time_begin)/CLOCKS_PER_SEC<<endl;

		}
	}
	cout << "Goal cannot be reached" << endl;
	exit(0);
}

int main() {
	cv::Mat obs_img = cv::imread("C:/Users/Lenovo/Desktop/map.jpg", 0);

	int h = obs_img.rows, w = obs_img.cols;

	cv::Mat canny;
	vector<vector<cv::Point> > obs;
	vector<cv::Vec4i> hierarchy;

	cv::Canny(obs_img, canny, 100, 200, 3);
	cv::findContours(canny, obs, hierarchy, CV_RETR_TREE, CV_CHAIN_APPROX_SIMPLE, cv::Point(0, 0));

	cv::Mat drawing = cv::Mat::zeros(canny.size(), CV_8UC3);
	for (int i = 0; i < obs.size(); i++)
	{
		cv::Scalar color = cv::Scalar(rng.uniform(0, 255), rng.uniform(0, 255), rng.uniform(0, 255));
		drawContours(drawing, obs, i, color, 2, 8, hierarchy, 0, cv::Point());
	}

	cout << obs.size() << endl;
	cout << h << endl << w << endl;
	//imshow("Contours", drawing);

	//h = 原图的高度
	//w = 原图的宽度
	bool** obs_map = new bool*[h];
	for (int i = 0; i < h; i++)
	{
		obs_map[i] = new bool[w];
		for (int j = 0; j < w; j++)
			obs_map[i][j] = !(obs_img.at<uchar>(i, j) >= 120);
	}

	State start(50, 90, 0);
	State target(1, 20, 0);
	Vehicle car;
	

	Planner astar;
	//path.push_back(start);
	//path.push_back(target);

	Map map(obs_map, target, obs);                          //object of Map class
	map.initCollisionChecker();
	//display.draw_obstacles(obs_map);
	//display.draw_car(path[0], car);
	//display.draw_car(path[1], car);
	//display.show(1);
	cout << "--------" << endl;
	vector<State> path = astar.plan(start, target, obs_map, car, obs);
	cout << "--------" << endl;
	GUI display(1000, 1000);
	display.draw_obstacles(obs_map);
	for (int i = 0; i <= path.size(); i++)
	{
		display.draw_car(path[i], car);
		display.show(1);
	}
	display.show();
	/*
	cv::Mat mat(1000,1000,CV_8U, cv::Scalar(0,0,0));
	for (int i = 0; i < h; i++)
	{
		for (int j = 0; j < w; j++)
			if (obs_map[i][j] == 0) {
				mat.at<uchar>(i, j) = 0;
			}
			else {
				//cout << map.acc_obs_map[i][j] << endl;
				mat.at<uchar>(i, j) = 255;
			}
	}
	imshow("Contours", mat);
	*/
	

	cv::waitKey(0);
	return 0;
}
#endif