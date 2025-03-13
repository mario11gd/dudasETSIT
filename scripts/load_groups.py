import sqlite3

def load_group(group_name):
    try:
        try:
            con = sqlite3.connect('instance/dudasETSIT.db')
        except:
            print("An error occured while trying to connect to the database")
            return 1
        
        cur = con.cursor()
        cur.execute(f"""
            INSERT INTO "group" (name) VALUES
                ('{group_name}')
        """)
        con.commit()
        print(f"Group {group_name} loaded to sqlite database")
        return 0
    except:
        print(f"An error occured while trying to load group {group_name} to sqlite database")
        return 1

if __name__ == "__main__":
    load_group("1ºGISD")
    load_group("2ºGISD")
    load_group("3ºGISD")
    load_group("4ºGISD")