#include <iostream>
#include <ctime>
#include <cstdio>
#include <cstdlib>

using namespace std;

int main () {
  time_t t;
  unsigned int seed = time(0ll);
  while (seed <= 10) {
    srand(seed++);
    printf("%d\n", rand());
  }
  //srand(1);
//  for (int i = 0; i < 10; i++) {
//  }
  return 0;
}
