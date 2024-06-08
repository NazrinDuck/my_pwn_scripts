#include <iostream>
#include <ctime>
#include <cstdio>
#include <cstdlib>

using namespace std;

int main () {
  time_t t;
  unsigned int seed = 0;
  srand(seed);
  for (int i = 0; i <= 10; i++) {
    printf("%d\n", (rand() % 6) + 1);
  }
  return 0;
}
