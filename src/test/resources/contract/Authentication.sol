pragma solidity >=0.4.24 <0.6.11;

import "./Table.sol";

contract Authentication {
    // event
    event RegisterEvent(int256 ret, string indexed account_id, string  public_key, string  user_info, string  sig_data);
    
    constructor() public {
        createTable();
    }

    function createTable() private {
        TableFactory tf = TableFactory(0x1001); 
        tf.createTable("t_identity", "account_id","public_key,user_info,sig_data");
    }

    function openTable() internal returns(Table) {
        TableFactory tf = TableFactory(0x1001);
        Table table = tf.openTable("t_identity");
        return table;
    }


    function select(string memory account_id) public view returns(int256, string , string , string) {
        TableFactory tf = TableFactory(0x1001);
        Table table = tf.openTable("t_identity");
        Entries entries = table.select(account_id, table.newCondition());
        string memory public_key = "";

        if (0 == uint256(entries.size())) {
            return (-1, public_key,public_key,public_key);
        } else {
            Entry entry = entries.get(0);
            return (0, string(entry.getString("public_key")), string(entry.getString("user_info")) ,string(entry.getString("sig_data")));
        }
    }

    function register(string memory account_id, string  public_key, string  user_info, string  sig_data) public returns(int256){
        int256 ret_code = 0;
        int256 ret= 0;
        string memory temp_value = "";
        (ret, temp_value,temp_value,temp_value) = select(account_id);
        if(ret != 0) {
            Table table = openTable();       
            Entry entry = table.newEntry();
            entry.set("account_id", account_id);
            entry.set("public_key", public_key);
            entry.set("user_info", user_info);
            entry.set("sig_data", sig_data);
            int count = table.insert(account_id, entry);
            if (count == 1) {
                ret_code = 0;
            } else {
                ret_code = -2;
            }
        } else {
            ret_code = -1;
        }
        emit RegisterEvent(ret_code, account_id, public_key, user_info, sig_data);
        return ret_code;
    }

    
}

