#include <opencv/cv.h>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/core/core.hpp>
#include <assert.h>
#include <iostream>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace std;


void createAlphaMat( Mat &mat ){

    for( int i = 0; i < mat.rows; i++ ){
        for( int j = 0; j < mat.cols; j++ ){
            //顺序是b,g,r,a
            Vec4b &rgba = mat.at<Vec4b>(i,j);
            rgba[0] = 0x0;
            rgba[1] = 0x0;
            rgba[2] = 0xff;
            rgba[3] = 0x0;
        }
    }

    return;
}


void funsion(){
    Mat img1 = imread("./1");
    Mat img2 = imread("./2");
    cvNamedWindow( "example1",CV_WINDOW_AUTOSIZE );
    cvNamedWindow( "example2",CV_WINDOW_AUTOSIZE );

    
    //起始横偏移，纵偏移，横大小，纵大小
    Mat imageRoi = img2( Rect(160,0,128,128) );
    addWeighted( imageRoi,0.1,img1,0.3,0.0,imageRoi );

    imshow("example2",img2 );
    waitKey();

    return;
}



int g_draw = 0;
Rect g_rectangle;
void DrawRectangle( Mat &img,Rect &box ){
    //hdc,左上角point，右下角point,颜色，线粗，线型
    rectangle( img,box.tl(),box.br(),Scalar(0xff,0x0,0),3,20 );
    return;
}


void MouseCallBack( int event,int x,int y,int flags,void *param ){

    if( event == EVENT_LBUTTONDOWN ){
        g_rectangle = Rect(x,y,0,0);
        g_draw = 1;
    }else if( event == EVENT_LBUTTONUP ){
        g_draw = 0;
        if( g_rectangle.width < 0 ){
            g_rectangle.x += g_rectangle.width;
            g_rectangle.width *= -1;
        }
        if( g_rectangle.height < 0 ){
            g_rectangle.y += g_rectangle.height;
            g_rectangle.height *= -1;
        }
        DrawRectangle( *(Mat *)param,g_rectangle );
    }else if( event == EVENT_MOUSEMOVE ){
        if( g_draw == 1 ){
            g_rectangle.width = x - g_rectangle.x;
            g_rectangle.height = y - g_rectangle.y;
        }
    }else{
        return;
    }
    return;
}


int main( int argc, char** argv )
{

    //第二个参数表示色彩通道,默认值1表示3通道彩色/higui_c.h
    //0为8bit灰度图
    Mat BackGround(600,800,CV_8UC3);

    //第二个参数默认CV_WINDOW_AUTOSIZE
    cvNamedWindow( "example",CV_WINDOW_AUTOSIZE );

    imshow("example",BackGround );

    setMouseCallback( "example",MouseCallBack,&BackGround );
    //waitKey();
    while(1){
        imshow("example",BackGround );
        if( waitKey( 10 ) == 27 )
            break;
    }

#if 0
    //高，宽，色彩类型
    Mat pic(320,640,CV_8UC4);
    createAlphaMat( pic );

    //一参要带后缀
    //bool imwrite( const string &filenam,InputArray img,const vector<int>& params = vector<int>() );
    //三参是特定格式的参数编码,先压入一个flag的意义，之后压入jpeg为0-100的质量，png为0-9压缩级别等等
    //bool imwrite( const string &filenam,InputArray img,const vector<int>& params = vector<int>() );
    //ret = 1为成功
    int ret = imwrite( "tmp.jpg",pic );

#endif


    //funsion();


    return 0;
}
