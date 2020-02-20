#include<iostream>
#include<cstdlib>
#include<assert.h>

using namespace std;

class input_iterator{};
class output_iterator{};
class forward_iterator : public output_iterator{};
class bidirectional_iterator : public forward_iterator{};
class random_iterator : public bidirectional_iterator{};

template<class T>
class Iterator_Traits{
	public:
		typedef typename T::value_type value_type;
		typedef typename T::pointer pointer;
		typedef typename T::reference reference;
		typedef typename T::difference_type difference_type;
		typedef typename T::iterator_category iterator_category;

};


template<class T>
class Iterator_Traits<T*>{
	public:
		typedef T value_type;
		typedef T *pointer;
		typedef T &reference;
		typedef ptrdiff_t difference_type;
		typedef random_iterator iterator_category;

};


template<class T>
class Iterator_Traits<const T*>{
	public:
		typedef T value_type;
		typedef const T *pointer;
		typedef const T &reference;
		typedef ptrdiff_t difference_yupe;
		typedef random_iterator iterator_category;

};


template<class Category,class T,class Distance = ptrdiff_t,class Pointer = T *,class Reference = T &>
class Iterator{
	public:
		typedef T value_type;
		typedef Pointer pointer;
		typedef Reference reference;
		typedef Distance difference_yupe;
		typedef Category iterator_category;

};

template<class T>
typename Iterator_Traits<T>::iterator_category
Iterator_category(T &){
	typedef typename iterator_traits<T>::iterator_category category;
	return category();
}

template<class T>
T *_allocate( size_t size,T * ){
	T *p = (T *)( ::operator new( size * sizeof(T) ) );
	assert( p );
	return p;
}

template<class T>
void _deallocate( T *p ){
	::operator delete( p );
	return;
}

template<class T>
void _construct( T *p,const T &value ){
	new(p)T(value);
	return;
}

template<class T>
void _destory( T *p ){
	p->~T();
	return;
}

template<class T>
class Allocator{
	public:

		typedef T value_type;
		typedef T *pointer;
		typedef const T *const_pointer;
		typedef T &reference;
		typedef const T &const_reference;
		typedef ptrdiff_t difference_type;
		typedef size_t size_type;

		template<class U>
			struct rebind{
				typedef allocator<U> other;	
			};

		static pointer allocate( size_type size ){
			return (pointer)::_allocate( size,(pointer)(0) );
		}

		static void deallocate( pointer p ){
			::_deallocate( p );
		}

		static void construct( pointer p,const_reference value ){
			::_construct( p,value );
		}

		static void destory( pointer p ){
			::_destory( p );
		}
	private:

};


template<class ForwardIterator,class T>
void uninitialized_fill_n(ForwardIterator first,size_t n,const T &value){
	while(n--){
		_construct(first,value);
		first++;
	}
	return;
}



template<class ForwardIterator,class T>
void uninitialized_fill(ForwardIterator first,ForwardIterator last,const T &value){
	while( first != last ){
		_construct(first,value);
		first++;
	}	
}


template<class InputIterator,class ForwardIterator>
ForwardIterator uninitialized_copy( InputIterator first,InputIterator last,ForwardIterator result){
	int i = 0;
	while( first !=last )
		_construct( result++,*first );
	return result;
}


template<class T,class Alloc = Allocator<T> >
class myVector{
	public:
		typedef T value_type;
		typedef value_type *pointer;
		typedef value_type &reference;
		typedef value_type *iterator;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;

		inline iterator begin(){
			return start;
		}
		inline iterator end(){
			return finish;
		}
		size_type size(){
			return (size_type)(finish - start);
		}
		bool empty(){
			return (start == finish);
		}
		reference operator[](size_type n){
			return *(start + n);
		}
		myVector():start(NULL),finish(NULL),vend(NULL){}
		myVector( size_type n,const T &value){
			fill_initialize( n,value );
		}

		reference front(){
			return *start;
		}

		reference back(){
			return *(finish - 1);
		}
		void push_back(const T &value){
			if( finish != vend ){
				_construct( finish,value );
				finish ++;
			}else{
				insert_aux( value );
			}
		}
		void insert_aux(const T &value){
			size_type nsize = size();
			iterator iter = data_allocator::allocate( (!nsize)?1:nsize * 2 );
			//copy
			for( int i = 0 ; i < size() ; i ++){
				_construct( iter + i,(*this)[i]);
				_destory( iter + i );
			}
			_deallocate( start );
			start = iter;
			vend = start + nsize * 2;
			finish = start + nsize;
			_construct( finish,value );
			finish++;

		}
		void pop_back(){
			--finish;
			destory(finish);
		}

		void erase(iterator position){
			if( position != finish ){
				;
			}else{
				_destory(position );
			}
		}



	private:
		typedef Alloc data_allocator;

		iterator start;
		iterator finish;
		iterator vend;

		void insert(iterator pos,const T &x);
		void deallocate(){

		}
		iterator allocate_and_fill( size_type n,const T &value ){
			iterator iter = data_allocator::allocate(n);
			uninitialized_fill_n( iter,n,value );
			return iter;
		}
		void fill_initialize( size_type n,const T &value ){
			start = allocate_and_fill( n,value );
			finish = vend = start + n;
		}
};





int main(){
	myVector<int> v(10,1);
	v.push_back(3);
	cout<<v.back()<<endl;
	return 0;
}
