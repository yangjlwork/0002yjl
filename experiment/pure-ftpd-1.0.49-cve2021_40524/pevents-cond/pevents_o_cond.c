/* pevents_o_cond —— 事件 o 的谓词条件 c_p（论文 §2.2 if(c_p) 的目标侧实现）。
 * 谓词：user_dir_size > user_quota（Table 1/Listing 2 原文）在 pure-ftpd 的
 * 运行时语义：配额机制激活（hasquota()==0）且当前用量超限（quota_update
 * 只读快照比较）。仅含性质谓词语义，无漏洞知识。
 */
#include <config.h>

#ifdef QUOTAS
#include <stddef.h>
#include <quotas.h>

/* ftpd.c 的全局（globals.h 经 GLOBAL 宏声明，此处直接 extern） */
extern unsigned long long user_quota_size;
extern unsigned long long user_quota_files;

int pevents_o_cond(void)
{
    Quota q;

    if (hasquota() != 0) {          /* 机制未激活：谓词必假 */
        return 0;
    }
    if (quota_update(&q, 0LL, 0LL, NULL) != 0) {   /* 只读当前用量 */
        return 0;
    }
    return (q.size > user_quota_size ||
            q.files >= user_quota_files) ? 1 : 0;
}
#else
int pevents_o_cond(void) { return 0; }
#endif
