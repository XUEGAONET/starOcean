# xsk

## 注意

* 目前来看，不推荐并发消费或者生产，会产生问题但是可控
* 字长为32bit的处理器在运行时，会出现64bit的数据的非原子性操作，这样在多消费者或者多生产者情况下，可能会造成不可控的问题
* 在所有计数操作能够确保原子性时，产生错误时，可能会丢包、重复发包