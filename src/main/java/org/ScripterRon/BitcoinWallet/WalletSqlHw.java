/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.ScripterRon.BitcoinWallet;

//import java.io.EOFException;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
//import java.util.Arrays;
import java.util.List;
//import java.util.logging.Level;
//import java.util.logging.Logger;
import javax.smartcardio.CardException;
import org.satochip.satochipclient.CardConnector;
import org.satochip.satochipclient.CardConnectorException;
//import org.satochip.client.JCconstants;
import org.ScripterRon.BitcoinCore.ECException;
import org.ScripterRon.BitcoinCore.ECKey;
import org.ScripterRon.BitcoinCore.ECKeyHw;
//import org.ScripterRon.BitcoinCore.EncryptedPrivateKey;
import static org.ScripterRon.BitcoinWallet.Main.log;

public class WalletSqlHw extends WalletSql{
    
    /** CardConnector object for javacard wallet */
    CardConnector cardConnector;    
    
    /** Applet AID*/
    byte[] byteAID= {0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70}; //SatoChip
                
    /** change path*/
    public static List<Integer> changePath; // change key (unique)
    private static List<Integer> currentPath;// last created key (path is simply incremented)
    
    /** Keys table definitions */
    private static final String Keys_Table_Hw = "CREATE TABLE IF NOT EXISTS KeysHw ("
            + "db_id                    IDENTITY,"                  // Row identity
            + "public_key               BINARY NOT NULL,"           // Public key
            + "timestamp                BIGINT NOT NULL,"           // Time key created
            + "label                    VARCHAR,"                   // Associated label or null
            + "is_change                BOOLEAN NOT NULL,"         // Is a change key
            + "is_BIP32                 BOOLEAN NOT NULL,"          // true for BIP32 false for STD key
            + "keypath                  BINARY NOT NULL)";          // key path coded as byte array
    
    /**
     * Create the Wallet
     *
     * @param       dataPath                Application data path
     * @throws      WalletException         Unable to initialize the database
     */
    public WalletSqlHw(String dataPath) throws WalletException{
        super(dataPath);
        
        if (!tableExists("KeyHw")) {
            createTables();
        }
        
        // connect to hw dongle
        cardConnector= new CardConnector(); 
        ECKeyHw.setCardConnector(cardConnector);
        // select applet
        log.info("cardConnector.cardSelect("+CardConnector.toString(byteAID)+")");
        try {
            cardConnector.cardSelect(byteAID);
        } catch (CardConnectorException ex) {
            log.error("CardConnectorException in cardSelect: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff),ex);
        }

        // change address
        changePath= new ArrayList<>(1);
        changePath.add(0xffffffff);
        // last main address
        currentPath= new ArrayList<>(1);
        currentPath.add(0x80000000); // start from 0x80000000 then increment for each new key
        
    }
    
     /**
     * Close the database
     */
    @Override
    public void close() {
        super.close();
        try {
            cardConnector.disconect();
        } catch (CardException ex) {
            log.error("Error during card disconnect", ex);
        }
    }
    
    /**
     * Create the database tables
     *
     * @throws      WalletException     Unable to create database tables
     */
    private void createTables() throws WalletException {
        Connection conn = getConnection();
        try (Statement s = conn.createStatement()) {
            // Create additional table
            s.executeUpdate(Keys_Table_Hw);
            log.info("SQL database Keys_Table_Hw created");
        } catch (SQLException exc) {
            log.error("Unable to create SQL database Keys_Table_Hw", exc);
            throw new WalletException("Unable to create SQL database Keys_Table_Hw");
        }
    }
    
    /**
     * Stores a key
     *
     * @param       key                 Public/private key pair
     * @throws      WalletException     Unable to store the key
     */
    @Override
    public void storeKey(ECKey key) throws WalletException {
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("INSERT INTO KeysHw "
            + "(public_key,timestamp,label,is_change,is_BIP32,keypath) VALUES(?,?,?,?,?,?)")) {  
            
            //timestamp used in case on block rescan
            key.setCreationTime((long)1400000000);
            
            s.setBytes(1, key.getPubKey());
            s.setLong(2, key.getCreationTime());
            if (key.getLabel().isEmpty())
                s.setNull(3, Types.VARCHAR);
            else
                s.setString(3, key.getLabel());
            s.setBoolean(4, key.isChange());
            s.setBoolean(5, ((ECKeyHw)key).isBIP32());
            s.setBytes(6, ((ECKeyHw)key).getKeypath());
            
            s.executeUpdate();
            log.info("Stored key in db: label:"+key.getLabel()
                        +" pubkey:"+CardConnector.toString(key.getPubKey())
                        +" keypath:"+CardConnector.toString(((ECKeyHw)key).getKeypath())
                        +" creationTime"+key.getCreationTime());
            
        } catch (SQLException exc) {
            log.error("Unable to store key", exc);
            throw new WalletException("Unable to store key");
        }
    }

    /**
     * Sets the key label
     *
     * @param       key                 Public/private key pair
     * @throws      WalletException     Unable to update the label
     */
    @Override
    public void setKeyLabel(ECKey key) throws WalletException {
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("UPDATE KeysHw SET label=? WHERE public_key=?")) {
            if (key.getLabel().isEmpty())
                s.setNull(1, Types.VARCHAR);
            else
                s.setString(1, key.getLabel());
            s.setBytes(2, key.getPubKey());
            s.executeUpdate();
        } catch (SQLException exc) {
            log.error("Unable to update key label", exc);
            throw new WalletException("Unable to update key label");
        }
    }

    /**
     * Returns a list of all keys sorted by the label
     *
     * @return                          List of keys stored in the database
     * @throws      KeyException        Private key does not match public key
     * @throws      WalletException     Unable to get address list
     */
    @Override
    public List<ECKey> getKeyList() throws KeyException, WalletException {
        List<ECKey> keyList = new ArrayList<>();
        Connection conn = getConnection();
        ResultSet r;
        try (Statement s = conn.createStatement()) {
            r = s.executeQuery("SELECT public_key,timestamp,label,is_change,is_BIP32,keypath FROM KeysHw "
                            + "ORDER BY label ASC NULLS FIRST");
            while (r.next()) {
                byte[] pubKey = r.getBytes(1);
                byte[] keypath= r.getBytes(6);
                boolean isChange= r.getBoolean(4);
                
                ECKey key;
                if (keypath.length==1){
                    key= new ECKeyHw(keypath[0], pubKey);
                }else{
                    List<Integer> bip32path= new ArrayList<>(keypath.length/4);
                    for (int i=0; i<keypath.length; i+=4){
                        long val= ((keypath[i]&0xff)<<24) ^ ((keypath[i+1]&0xff)<<16) ^ ((keypath[i+2]&0xff)<<8) ^ (keypath[i+3]&0xff);
                        bip32path.add((int)val);
                    }
                    if (bip32path.size()>1)
                        throw new KeyException("Bip32path longer than expected (should be 1)...");
                    if (!isChange && Integer.toUnsignedLong(bip32path.get(0))>Integer.toUnsignedLong(currentPath.get(0)))
                        currentPath.set(0, bip32path.get(0));
                    key= new ECKeyHw(bip32path, pubKey);
                }
                key.setCreationTime(r.getLong(2));
                String label = r.getString(3);
                key.setLabel(label!=null?label:"");
                key.setChange(isChange);
                keyList.add(key);
                
                log.info("Recovered key from db: label:"+key.getLabel()
                        +" pubkey:"+CardConnector.toString(key.getPubKey())
                        +" keypath:"+CardConnector.toString(((ECKeyHw)key).getKeypath()));
            
            }
        } catch (SQLException exc) {
            log.error("Unable to get key list", exc);
            throw new WalletException("Unable to get key list");
        }
        return keyList;
    }
    
    public static List<Integer> incrementCurrentPath(){
        log.info("increment path (before): size:"+currentPath.size()+" list[0]:"+currentPath.get(0)+" "+Integer.toHexString(currentPath.get(0)));
        long current= Integer.toUnsignedLong(currentPath.get(0));
        current++;
        currentPath.set(0,(int)current);
        log.info("increment path (after): size:"+currentPath.size()+" list[0]:"+ currentPath.get(0)+" "+Integer.toHexString(currentPath.get(0)));
        //currentPath.set(0, currentPath.get(0)+1); // sign mismatch?
        return currentPath;
    }
    
    public void hwWalletSetup(String strpin, String strublk) throws WalletException, CardConnectorException{
        
        try {
            // setup (done only once)
            byte pin_tries_0= 0x10;
            byte ublk_tries_0= 0x10;
            byte[] pin= strpin.getBytes("UTF-8");
            byte[] ublk= strublk.getBytes("UTF-8");
            
            log.info("PIN: "+CardConnector.toString(pin)+" PUK: "+CardConnector.toString(ublk));
            
            short secmemsize= 0x1000; 
            short memsize= 0x1000;
            
            byte create_object_ACL= 0x01;
            byte create_key_ACL= 0x01;
            byte create_pin_ACL= 0x01;
            
            cardConnector.cardSetup(
                    pin_tries_0, ublk_tries_0, pin, ublk,
                    pin_tries_0, ublk_tries_0, pin, ublk,
                    secmemsize, memsize,
                    create_object_ACL, create_key_ACL, create_pin_ACL);
        } catch (UnsupportedEncodingException ex) {
            throw new WalletException("Unable to convert pin or ublk to a byte array", ex);
        }
    }
    
    public boolean hwWalletSetupDone(){
        try {
            byte[] response= cardConnector.cardGetStatus(); // 
            log.info("Setup already done: cardConnector.cardGetStatus(): "+CardConnector.toString(response));
            return true;
        } catch (CardConnectorException ex) {
            log.info("Setup Not done (yet): CardConnectorException: "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
            return false;
        }
    }
    
    public boolean hwWalletVerifyPIN(byte pin_nbr, String strpin) throws WalletException, CardConnectorException{
        try {
            byte[] pin= strpin.getBytes("UTF-8");
            cardConnector.cardVerifyPIN(pin_nbr, pin);	
            return (cardConnector.getLastSW12()==0x9000);
        } catch (UnsupportedEncodingException ex) {
            throw new WalletException("Unable to convert PIN to a byte array", ex);
        }
    }
    
    public boolean hwWalletChangePIN(byte pin_nbr, String old_strpin, String new_strpin) throws WalletException, CardConnectorException{
        try {
            byte[] old_pin= old_strpin.getBytes("UTF-8");
            byte[] new_pin= new_strpin.getBytes("UTF-8");
            cardConnector.cardChangePIN(pin_nbr, old_pin, new_pin);
            return (cardConnector.getLastSW12()==0x9000);
        } catch (UnsupportedEncodingException ex) {
            throw new WalletException("Unable to convert old PIN or new PIN to a byte array", ex);
        }
    }
    
    public boolean hwWalletIsSeeded() {
        try {
            byte[] k= ECKeyHw.getBip32AuthentiKey();
            log.info("recovered authentikey: "+CardConnector.toString(k));
            return k!=null;
        } catch (ECException | CardConnectorException ex) {
            log.info("no authentikey");
            return false;
        }
    }
    public boolean hwWalletImportSeed(String strseed) throws WalletException, ECException{
        try {
            byte[] seed= strseed.getBytes("UTF-8");
            byte[] keyACL={0x00,0x01,0x00,0x01,0x00,0x01}; 
            byte[] k= ECKeyHw.importBip32Seed(keyACL, seed);
            log.info("recovered authentikey: "+CardConnector.toString(k));
            return k!=null;
        } catch (UnsupportedEncodingException ex) {
            throw new WalletException("Unable to convert seed to a byte array", ex);
        } catch (CardConnectorException ex) {
            throw new WalletException("Unable to recover public authentikey during seed import: ins:"+ex.getIns()+" sw12:"+ex.getSW12(), ex);
        }
    }
        
}
