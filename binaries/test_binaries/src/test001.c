#include <stdio.h>
#include <stdlib.h>

char gc1, gc2, gc3, gc4;

void f1(void);
void f2(void);
void f3(void);
void f4(void);
void f5(void);
void f6(void);
void f7(void);


void f1(void)
{
	f2();
}

void f2(void)
{
	f3();
	f4();
	f4();
	f5();
	f6();
	f7();
}

void f3(void)
{
	f2();
}

void f4(void)
{
	gc1 = 'a';
	
}

void f5(void)
{
	printf("%c\n", gc1);
}

void f6(void)
{
	gc1 = 'b';
	gc2 = 'c';
	gc3 = 'd';
}

void f7(void)
{
	gc2 = 'b';
	gc3 = 'c';
	gc4 = 'e';
}

int main(void)
{
	f1();
	return EXIT_SUCCESS;
}
