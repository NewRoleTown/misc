/*
 * cppprimer.cpp
 *
 *  Created on: 2013.11.24
 *      Author: Caroline
 */

/*eclipse cdt, gcc 4.8.1*/

#include <iostream>
#include <memory>

using namespace std;

void deleter (int* ptr) {
	delete[] ptr;
	ptr = nullptr;
	std::clog << "shared_ptr delete the pointer." << std::endl;
}

int main (void) {

	typedef void (*tp) (int*);

	std::unique_ptr<int[], tp> upi4(new int[20], deleter);

	//std::cout << "*upi4 = " << *upi4 << std::endl;

	return 0;

}

