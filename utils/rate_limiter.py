import time

def wait_for_rate_limit(max_qps: float, last_call_time: float) -> float:
    """
    等待直到可以安全发起下一个请求
    
    :param max_qps: 每秒最大请求数
    :param last_call_time: 上次调用的时间戳
    :return: 本次调用的时间戳
    """
    if max_qps <= 0:
        return time.time()
        
    interval = 1.0 / max_qps
    current_time = time.time()
    elapsed = current_time - last_call_time
    wait_time = max(0, interval - elapsed)
    
    if wait_time > 0:
        time.sleep(wait_time)
    
    return time.time()
