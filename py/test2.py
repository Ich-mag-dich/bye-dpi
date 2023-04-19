import psutil

def get_net_if_stats():
    net_if_stats = psutil.net_if_stats()
    return net_if_stats

if __name__ == "__main__":
    ifstats = get_net_if_stats()
    for proc in ifstats:
        print(f"{proc}: {ifstats[proc]}")
