#include<iostream>
#include<vector>
#include<unistd.h>
#include<algorithm>
#include<assert.h>

using namespace std;

class Vnode;
typedef struct _Es{
	Vnode *node;
	int weight;
	struct _Es *next;

	int less;
}Es;


class Vnode{
	public:
#define WHITE 0
#define GRAY 1
#define BLACK -1

		int distance;
		Vnode *parent;
		int key;
		Es *Elist;
		int color;

		int time_in;
		int time_out;

		int flow;

};

class Graphics{

	public:

		int graphics_size;
		Graphics();
		~Graphics();

		Es *edge_exist(int from,int to);

		int dfs(int index);
		int dfstime;

		int bfs(int index);

		int dijkstra(int from,int to);


		int relax(int from,int to);
		int Bellman_Ford(int s);


		int get_min_edge_not_in_set(vector<Vnode *> set,int *from,int *to);
		int prim();

		int add_edge(int from,int to,int weight);
		int add_node();
		int clean();


		int find_flow_path(int from,int to);
		int update_flow_path(int t);
		int maxflow();
		int add_flow(int from,int to,int delta);
		int flow_clear_flags();


		int kosarajo();
		int find_max_outtime_node_index(vector<Vnode *> set);
		int dfs_for_Scc(int index,vector<Vnode *> &set);

		vector<Vnode *> Vset;
		vector<Vnode *> tree;
		vector<vector<Vnode *> > Scc;

		int tree_weight;
};

//dp[days][cli] = dp[days + 1][cli + 1] + dp[days + 1][cli + 2]

int Graphics::relax(int from,int to){
	Es *p = edge_exist(from,to);
	if(!p)return -1;

	if(Vset[from]->distance + p->weight < Vset[to]->distance){
		Vset[to]->distance = Vset[from]->distance + p->weight;
		Vset[to]->parent = Vset[from];
		return 0;
	}

	return 1;
}

int Graphics::Bellman_Ford(int s){
	int i = 0,j = 0;
	for(; i < Vset.size(); i++)
		Vset[i]->distance = 0x7fffffff;	

	Vset[s]->distance = 0;

	int have_negtive_loop = 0;

	for(i = 0; i < Vset.size() - 1; i++){
		for(j = 0; j < Vset.size(); j++){

			Es *p = Vset[j]->Elist;
			while(p){
				if(relax(j,p->node->key) == -1){
					assert(0);
				}
				p = p->next;
			}

		}
	}

	for(j = 0; j < Vset.size(); j++){

		Es *p = Vset[j]->Elist;
		while(p){
			if(relax(j,p->node->key) == 0){
				have_negtive_loop = 1;
				break;
			}
			p = p->next;
		}

	}


	return have_negtive_loop;
}

int Graphics::dfs_for_Scc(int index,vector<Vnode *> &set){
	set.push_back(Vset[index]);
	Vset[index]->color = GRAY;

	Es *p = Vset[index]->Elist;
	while(p){
		if(p->node->color == WHITE)
			dfs_for_Scc(p->node->key,set);
		p = p->next;
	}
	Vset[index]->color = BLACK;
	return 0;
}

int Graphics::find_max_outtime_node_index(vector<Vnode *> set){
	int index = -1;
	for(int i = 0; i < set.size(); i++){
		if(Vset[i]->color != WHITE)continue;
		if(index == -1){
			index = i;
			continue;
		}
		if(Vset[index]->time_out < Vset[i]->time_out)
			index = i;
	}
	//cout<<index;
	return index;
}

int Graphics::kosarajo(){
	Graphics revGr;
	int from,to;
	int i = graphics_size;

	while(i--)
		revGr.add_node();

	for(from = 0; from < graphics_size; from++){
		for(to = from + 1; to < graphics_size; to++){
			if(edge_exist(from,to)){
				if(!edge_exist(to,from)){
					revGr.add_edge(to,from,0);
				}else{
					revGr.add_edge(to,from,0);
					revGr.add_edge(from,to,0);
				}
			}
			else if(edge_exist(to,from)){
				revGr.add_edge(from,to,0);
			}
		}
	}

	this->dfs(0);

	for(i = 0; i < Vset.size(); i++){
		revGr.Vset[i]->time_out = Vset[i]->time_out;
	}


	int index = -1;
	while((index = revGr.find_max_outtime_node_index(revGr.Vset)) != -1){
		vector<Vnode *> set;
		revGr.dfs_for_Scc(index,set);
		for(i = 0 ; i < set.size(); i++)
			cout<<set[i]->key<<" ";
		cout<<endl;
		Scc.push_back(set);	
	}


	return 0;
}

Es *Graphics::edge_exist(int from,int to){
	Es *p = Vset[from]->Elist;

	while(p){
		if(p->node->key == to)
			return p;
		p = p->next;
	}

	return NULL;
}

int Graphics::dfs(int index){
	if(Vset[index]->color != WHITE)return -1;
	Vset[index]->color = GRAY;
	Vset[index]->time_in = dfstime++;
	Es *p = Vset[index]->Elist;
	while(p){
		if(WHITE == p->node->color){
			p->node->parent = Vset[index];
			p->node->distance = p->node->parent->distance + p->weight;
			dfs(p->node->key);
		}
		p = p->next;
	}
	Vset[index]->color = BLACK;
	Vset[index]->time_out = dfstime++;

}

int Graphics::bfs(int index){
	vector<Vnode *> queue;

	Vset[index]->color = GRAY;
	queue.push_back(Vset[index]);

	while(!queue.empty()){
		Vnode *p = *queue.begin();
		queue.erase(queue.begin());
		cout<<p->key<<endl;

		Es *pE = p->Elist;
		while(pE){
			if(pE->node->color == WHITE){
				pE->node->color = GRAY;
				pE->node->parent = p;
				pE->node->distance = p->distance + pE->weight;
				queue.push_back(pE->node);
			}
			pE = pE->next;

		}
		p->color = BLACK;
	}

	return 0;
}

int Graphics::clean(){
	int i;
	for(i = 0; i < graphics_size; i++){
		Vset[i]->parent = NULL;
		Vset[i]->distance = 0;
		Vset[i]->color = WHITE;
	}
	return 0;
}

int Graphics::dijkstra(int from,int to){
	for(int i = 0; i < Vset.size(); i++)
		Vset[i]->distance = 0x7fffffff;
	Vset[from]->distance = 0;
	vector<Vnode *> Vless = Vset;
	vector<Vnode *> tmp;


	while(Vless.size()){
		int min = 0;
		for(int i = 0; i < Vless.size(); i++){
			if(Vless[i]->distance < Vless[min]->distance)
				min = i;
		}

		int index_global = Vless[min]->key;
		tmp.push_back(Vset[index_global]);
		vector<Vnode *>::iterator it = find(Vless.begin(),Vless.end(),Vless[min]);
		if(it == Vless.end())
			assert(0);
		Vless.erase(it);

		Es *p = Vset[index_global]->Elist;
		while(p){
			relax(index_global,p->node->key);
			p = p->next;
		}
	

	}


	return 0;
}

int Graphics::get_min_edge_not_in_set(vector<Vnode *> set,int *from,int *to){
	int inner_from = -1;
	int inner_to = -1;
	int min_edge = 0x7fffffff;
	int i = 0;

	for(; i < set.size(); i++){
		Es *p = set[i]->Elist;
		while(p){
			if(p->weight < min_edge && set.end() == find(set.begin(),set.end(),p->node)){
				inner_from = set[i]->key;
				inner_to = p->node->key;
				min_edge = p->weight;
			}
			p = p->next;
		}
	}

	cout<<min_edge<<endl;

	*from = Vset[inner_from]->key;
	*to = Vset[inner_to]->key;

	return min_edge;
}

int Graphics::prim(){
	int i = 0;
	int from = -1;
	int to = -1;

	tree.push_back(Vset[0]);
	//bug,only some cases can do this

	while(tree.size() != Vset.size()){
		tree_weight += get_min_edge_not_in_set(tree,&from,&to);
		tree.push_back(Vset[to]);
	}


	return 0;
}

int Graphics::add_edge(int from,int to,int weight){
	if(from >= graphics_size){
		cout<<"no from node"<<endl;
		return -1;
	}

	if(to >= graphics_size){
		cout<<"no to node"<<endl;
		return -1;
	}

	if(from == to ){
		cout<<"it's a loop"<<endl;
		return -1;
	}


	Es *pE = new Es;
	pE->node = Vset[to];
	pE->next = NULL;
	pE->weight = weight;
	pE->less = pE->weight;

	Es *ptmp = Vset[from]->Elist;
	if(!ptmp){
		Vset[from]->Elist = pE;
		return 0;
	}

	if(pE->node->key < ptmp->node->key){
		pE->next = ptmp;
		Vset[from]->Elist = pE;
		return 0;
	}

	while(ptmp->next){
		if(pE->node->key > ptmp->next->node->key)
			ptmp = ptmp->next;
		else
			break;
	}

	pE->next = ptmp->next;
	ptmp->next = pE; 
	return 0;


}

int Graphics::add_node(){

	Vnode *pnode = new Vnode;
	pnode->parent = NULL;
	pnode->Elist = NULL;
	pnode->key = graphics_size;
	pnode->distance = 0;
	pnode->color = WHITE;


	Vset.push_back(pnode);
	graphics_size ++;

	return 0;
}

int Graphics::flow_clear_flags(){
	int i  = 0;
	for(; i < Vset.size(); i++){
		Vset[i]->parent = NULL;
		Vset[i]->flow = 0;
		Vset[i]->color = WHITE;
	}
	Vset[0]->flow = 0x7fffffff;
	return 0;
}

int Graphics::maxflow(){
	int from;
	int to;
	for(from = 0; from < Vset.size(); from++){
		for(to = 0; to < Vset.size(); to++){
			if(from == to)continue;
			if(-1 == add_flow(from,to,0)){
				add_edge(from,to,0);
			}
		}
	}


	int flow = 0;
	do{
		flow_clear_flags();
		flow += find_flow_path(0,graphics_size - 1);
		if(Vset[graphics_size - 1]->flow == 0)break;
		update_flow_path(graphics_size - 1);

	}while(1);

	return flow;
}


/*

*/
int Graphics::find_flow_path(int from,int to){

	Vset[from]->color = GRAY;
	if(from == to)return Vset[to]->flow;

	Es *p = Vset[from]->Elist;
	int ret;
	while(p){
		if(!p->node->color && p->less > 0){
			p->node->parent = Vset[from];
			if(Vset[from]->flow > p->less){
				p->node->flow = p->less;
			}else{
				p->node->flow = Vset[from]->flow;
			}
			if(ret = find_flow_path(p->node->key,to)){
				return ret;
			};
		}
		p = p->next;
	}
	Vset[from]->color = BLACK;
	return 0;
}
int Graphics::add_flow(int from,int to,int delta){
	Es *p = Vset[from]->Elist;
	while(p){
		if(p->node->key == to){
			p->less -= delta;
			return 0;
		}
		p = p->next;
	}

	return -1;
}


int Graphics::update_flow_path(int t){
	int cur = t;
	int delta = Vset[t]->flow;
	while(1){
		int par = Vset[cur]->parent->key;
		add_flow(par,cur,delta);
		add_flow(cur,par,-delta);

		if(NULL == Vset[par]->parent)break;
		cur = Vset[cur]->parent->key;
	}
	return 0;
}

Graphics::Graphics(){
	graphics_size = 0;
	dfstime = 0;
	tree_weight = 0;
}

Graphics::~Graphics(){

}

int main(){

 Graphics Gr;

   Gr.add_node();
   Gr.add_node();
   Gr.add_node();

   Gr.add_node();
   Gr.add_node();
   Gr.add_node();

   Gr.add_node();
   Gr.add_node();
   Gr.add_node();



   Gr.add_edge(0,1,4);
   Gr.add_edge(1,0,4);


   Gr.add_edge(0,7,8);
   Gr.add_edge(7,0,8);

   Gr.add_edge(1,2,8);
   Gr.add_edge(2,1,8);

   Gr.add_edge(1,7,11);
   Gr.add_edge(7,1,11);

   Gr.add_edge(2,3,7);
   Gr.add_edge(3,2,7);

   Gr.add_edge(2,5,4);
   Gr.add_edge(5,2,4);

   Gr.add_edge(2,8,2);
   Gr.add_edge(8,2,2);

   Gr.add_edge(3,4,9);
   Gr.add_edge(4,3,9);

   Gr.add_edge(3,5,14);
   Gr.add_edge(5,3,14);

   Gr.add_edge(4,5,10);
   Gr.add_edge(5,4,10);

   Gr.add_edge(5,6,2);
   Gr.add_edge(6,5,2);

   Gr.add_edge(6,7,1);
   Gr.add_edge(7,6,1);

   Gr.add_edge(6,8,6);
   Gr.add_edge(8,6,6);

   Gr.add_edge(7,8,7);
   Gr.add_edge(8,7,7);
   Gr.prim();
    /*
	Graphics Gr;

	Gr.add_node();
	Gr.add_node();
	Gr.add_node();
	Gr.add_node();
	Gr.add_node();

	Gr.add_edge(0,1,6);
	Gr.add_edge(0,3,7);

	Gr.add_edge(1,2,5);
	Gr.add_edge(1,3,8);
	Gr.add_edge(1,4,4);

	Gr.add_edge(2,1,2);

	Gr.add_edge(3,2,3);
	Gr.add_edge(3,4,9);

	Gr.add_edge(4,2,7);
	Gr.add_edge(4,0,2);

	Gr.dijkstra(0,0);
	cout<<Gr.Vset[0]->distance<<endl;
	cout<<Gr.Vset[1]->distance<<endl;
	cout<<Gr.Vset[2]->distance<<endl;
*/
	return 0;
}






/*
   prim() test data
   Gr.add_node();
   Gr.add_node();
   Gr.add_node();

   Gr.add_node();
   Gr.add_node();
   Gr.add_node();

   Gr.add_node();
   Gr.add_node();
   Gr.add_node();



   Gr.add_edge(0,1,4);
   Gr.add_edge(1,0,4);


   Gr.add_edge(0,7,8);
   Gr.add_edge(7,0,8);

   Gr.add_edge(1,2,8);
   Gr.add_edge(2,1,8);

   Gr.add_edge(1,7,11);
   Gr.add_edge(7,1,11);

   Gr.add_edge(2,3,7);
   Gr.add_edge(3,2,7);

   Gr.add_edge(2,5,4);
   Gr.add_edge(5,2,4);

   Gr.add_edge(2,8,2);
   Gr.add_edge(8,2,2);

   Gr.add_edge(3,4,9);
   Gr.add_edge(4,3,9);

   Gr.add_edge(3,5,14);
   Gr.add_edge(5,3,14);

   Gr.add_edge(4,5,10);
   Gr.add_edge(5,4,10);

   Gr.add_edge(5,6,2);
   Gr.add_edge(6,5,2);

   Gr.add_edge(6,7,1);
   Gr.add_edge(7,6,1);

   Gr.add_edge(6,8,6);
   Gr.add_edge(8,6,6);

   Gr.add_edge(7,8,7);
   Gr.add_edge(8,7,7);
   Gr.prim();

*/


/*
   maxflow test data
   int i = 6;
   while(i--)
   Gr.add_node();

   Gr.add_edge(0,1,16);
   Gr.add_edge(0,2,13);
   Gr.add_edge(1,2,10);
   Gr.add_edge(1,3,12);
   Gr.add_edge(2,1,4);
   Gr.add_edge(2,4,14);
   Gr.add_edge(3,2,9);
   Gr.add_edge(3,5,20);
   Gr.add_edge(4,3,7);
   Gr.add_edge(4,5,4);

   cout<<Gr.maxflow();

*/


/*

   kosara test
   int i = 8;
   while(i -- )
   Gr.add_node();

   Gr.add_edge(0,1,10);
   Gr.add_edge(1,2,10);
   Gr.add_edge(1,4,10);
   Gr.add_edge(1,5,10);
   Gr.add_edge(2,3,10);
   Gr.add_edge(2,6,10);
   Gr.add_edge(3,2,10);
   Gr.add_edge(3,7,10);
   Gr.add_edge(4,0,10);
   Gr.add_edge(4,5,10);
   Gr.add_edge(5,6,10);
   Gr.add_edge(6,5,10);
   Gr.add_edge(6,7,10);

   Gr.kosarajo();
*/
