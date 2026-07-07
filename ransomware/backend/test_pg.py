import sys

def test_conn():
    try:
        import psycopg2
    except ImportError:
        print("psycopg2 not installed.")
        return

    hosts = ["127.0.0.1", "localhost"]
    passwords = [
        "postgres",
        "password",
        "admin",
        "root",
        "",
        "Test@1234",
        "Anmol@123",
        "Anmol@1234",
        "anmol",
        "Anmol",
        "12345678",
        "123",
        "1234"
    ]
    
    for host in hosts:
        for pwd in passwords:
            try:
                conn = psycopg2.connect(dbname="postgres", user="postgres", password=pwd, host=host, port=5432)
                print(f"SUCCESS: Connected to host={host} user=postgres password='{pwd}'")
                conn.close()
                return
            except Exception as e:
                # Just continue to next combination
                pass
                
    print("Failed to find working PostgreSQL credentials.")

if __name__ == "__main__":
    test_conn()
