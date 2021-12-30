#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;
printf ("argc %d\n", argc);
  for (i = 0; i < argc; i++)
    printf ("In loop%s\n", argv[i]);
  printf ("\n");

  return EXIT_SUCCESS;
}
