# napi_ed25519_async
## мотивация

Я не нашел ниодной многопоточной библиотеки для работы с ed25519 для nodejs, и потому написал свою

## install

    npm i hu2prod/napi_ed25519_async

## usage

 * see ./test.coffee
 * для запуска test.coffee нужно сделать `npm i ed25519`
 * Нет async версии для make keypair (но скорее это никому не понадобится, если нужно, пишите issue, сделаю, там несложно)

## benchmark

    UV_THREADPOOL_SIZE=undefined
    bench sign
    seq base 676.62
    par mod  2380.95
    no_alloc 2641.88
    bench verify
    seq base 203.09
    par mod  857.14


    UV_THREADPOOL_SIZE=32
    bench sign
    seq base 765.41
    par mod  3663.37
    no_alloc 5434.78
    bench verify
    seq base 239.28
    par mod  4851.49

## credits

 * used source from https://github.com/dazoe/ed25519
