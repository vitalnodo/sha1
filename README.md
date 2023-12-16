to run benchmark:
```gcc -O3 benchmark.c sha1.c unrolled/sha1u.c && ./a.out```


to show some tests:
```gcc test.c sha1.c && ./a.out```

On my machine this gives around 122 mb/sec, unrolled gives 395 mb/sec