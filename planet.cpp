#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
using namespace std;

string str = "abcdefghijklmnopqrstuvwxyz";
char a[31] = {0};

int main() {
  time_t t;
  unsigned int seed = time(0ll);
  srand(seed);

  for (int i = 0; i < 30; i++) {
    a[i] = str[rand() % 26];
  }
  cout << a;
  return 0;
}
// secret_passwd_anti_bad_guys
