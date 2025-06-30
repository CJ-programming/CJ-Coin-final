from json import loads

from sqlite3 import connect
from sqlite3 import Cursor
from typing import Any

def init_blockchain():
    with connect('blockchain.db') as conn:
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS header (
            version REAL NOT NULL,
            prev_hash TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            nbits INTEGER NOT NULL,
            nonce INTEGER NOT NULL,
            hash TEXT NOT NULL,
            height INTEGER NOT NULL,
            blocksize INTEGER NOT NULL,
            PRIMARY KEY (hash, height)
        )
        ''')    

        cursor.execute('''CREATE TABLE IF NOT EXISTS txs (
            version TEXT NOT NULL,
            inputs TEXT NOT NULL,
            outputs TEXT NOT NULL,
            signature TEXT NOT NULL,
            txid TEXT NOT NULL,
            block_hash TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            PRIMARY KEY (txid),
            FOREIGN KEY (block_hash, block_height) REFERENCES header (hash, height)
        )
        ''')

def init_peers():
    with connect('peers.db') as conn:
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS peers_set (
            version REAL NOT NULL,
            services TEXT NOT NULL,
            ipv4_address TEXT NOT NULL,
            port INT NOT NULL,
            node_id TEXT NOT NULL,
            status INTEGER NOT NULL,
            PRIMARY KEY (node_id)
        )
        ''') # status will either be 1 for up, and 0 for down

def init_utxos():
    with connect('utxos.db') as conn:
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS utxos_set (
            txid TEXT NOT NULL,
            output_index INTEGER NOT NULL,
            amount REAL NOT NULL,    
            address TEXT NOT NULL,
            PRIMARY KEY (txid, output_index)
        )   
        ''')

def read_db(cursor : Cursor, table : str, cols, params='', single_value=None) -> Cursor:
    if single_value:
        cursor.row_factory = lambda cursor, row : row[0]

    query = f"SELECT {','.join(str(col) for col in cols)} FROM {table}"

    cursor.execute(query, params)
 
    return cursor

def create_placeholder_str(cols):
    placeholder_str = ''

    for col in cols:
        placeholder_str += f"'{col}', ?, "

    return placeholder_str[:-2]

def read_db_json(cursor : Cursor, table : str, cols, convert_cols=(), params='') -> Cursor:
    if isinstance(convert_cols, str):
        convert_cols = (convert_cols,)

    db_values = read_db(cursor, table, cols, params).fetchall()

    json_values = []

    if cols == '*':
        column_names = get_column_names_db(cursor, table)

        for item in db_values:
            json_dict = dict()

            for col, entry in zip(column_names, item):
                if col in convert_cols:
                    converted_string = loads(entry)
                    json_dict.update({col : converted_string})

                else:
                    json_dict.update({col : entry})

            json_values.append(json_dict)

    else:
        for item in db_values:
            json_dict = {}

            for col, entry in zip(cols, item):
                if col in convert_cols:
                    converted_string = loads(entry)
                    json_dict.update({col : converted_string})

                else:
                    json_dict.update({col : entry})

            json_values.append(json_dict)

    return json_values

def get_cursor(db : str, timeout=5, check_same_thread=True) -> Cursor:
    with connect(db, timeout=timeout, check_same_thread=check_same_thread) as conn:
        cursor = conn.cursor()
    
    return cursor


def write_db(cursor : Cursor, table : str, cols : tuple, values : tuple) -> Cursor:
    query = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(values))})"

    cursor.execute(query, values)

    cursor.connection.commit()

def write_db_json(cursor : Cursor, table : str, json_data) -> Cursor:
    query = f"INSERT INTO {table} ({', '.join(json_data.keys())}) VALUES ({', '.join('?' * len(json_data))})"

    cursor.execute(query, tuple(json_data.values()))

    cursor.connection.commit()
    
def get_column_names_db(cursor : Cursor, table : str):
    columns = cursor.execute(f"PRAGMA table_info({table})").fetchall()

    column_names = [column[1] for column in columns]

    return column_names

def update_db(cursor: Cursor, table: str, primary_key_col : str, new_row: tuple, row_primary_key_val):
    column_names = get_column_names_db(cursor, table)

    update_query = f"UPDATE {table} SET "

    for column in column_names:
        update_query += f"{column} = ?, "

	# "UPDATE peers_set SET netaddr = ?, port = ? WHERE node_id = af7289h92dusu9h1994" what the query will look like

    update_query = update_query[:-2] # to exclude the unneccesary ", " at the end

    where_condition = f" WHERE {primary_key_col} = '{row_primary_key_val}'"

    update_query += where_condition
    
    cursor.execute(update_query, new_row)
    cursor.connection.commit()

def del_db(cursor : Cursor, table : str, params=None) -> Cursor:
    cursor.execute(f'DELETE FROM {table}', params)

    cursor.connection.commit()

def append_db(table : str, values : tuple, cursor : Cursor = None) -> None:
    cursor.execute(f'PRAGMA table_info({table})')
    table_info = cursor.fetchall()

    columns = (col[1] for col in table_info)

    write_db(cursor, table, columns, values)

def get_col_last_value(cursor : Cursor, table : str, col : str, params='') -> Any:
    last_value = read_db(cursor, f'{table} DESC LIMIT 1', (col,), params, True).fetchone()
    
    return last_value

def get_col_height(cursor, table : str, col : str, params='') -> int:
    cursor.row_factory = lambda cursor, row : row[0]
    col_height = cursor.execute(f'SELECT COUNT({col}) FROM {table}', params)

    return col_height
