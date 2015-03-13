/**
 * Copyright 2013-2014 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinWallet;

import org.ScripterRon.BitcoinCore.ECKey;
import org.ScripterRon.BitcoinCore.ECException;
import org.ScripterRon.BitcoinCore.BloomFilter;
import org.ScripterRon.BitcoinCore.ECKeyHw;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.PeerAddress;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.LogManager;
import javax.swing.*;
import org.satochip.satochipclient.CardConnector;
import org.satochip.satochipclient.CardConnectorException;
import org.satochip.satochipclient.JCconstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>BitcoinWallet is a wallet used for sending and receiving Bitcoins.  It supports labels
 * for send and receive addresses as well as a transaction safe.  Transactions in the safe
 * will not be used to create new transactions (that is, the bitcoins represented by these
 * transactions will not be spent).</p>
 *
 * <p>The main() method is invoked by the JVM to start the application.</p>
 */
public class Main {

    /** Logger instance */
    public static final Logger log = LoggerFactory.getLogger("org.ScripterRon.BitcoinWallet");

    /** Conversion value for BTC to Satoshi (1 Satoshi = 0.00000001 BTC) */
    private static final BigDecimal SATOSHI = new BigDecimal("100000000");

    /** File separator */
    public static String fileSeparator;

    /** Line separator */
    public static String lineSeparator;

    /** User home */
    public static String userHome;

    /** Operating system */
    public static String osName;

    /** Application identifier */
    public static String applicationID;

    /** Application name */
    public static String applicationName;

    /** Application version */
    public static String applicationVersion;

    /** Application lock file */
    private static RandomAccessFile lockFile;

    /** Application lock */
    private static FileLock fileLock;

    /** Application properties */
    public static Properties properties;

    /** Data directory */
    public static String dataPath;

    /** Application properties file */
    private static File propFile;

    /** Test network */
    private static boolean testNetwork = false;

    /** Main application window */
    public static MainWindow mainWindow;

    /** Message handler */
    private static MessageHandler messageHandler;

    /** Peer address */
    private static PeerAddress[] peerAddresses;

    /** Thread group */
    private static ThreadGroup threadGroup;

    /** Worker threads */
    private static final List<Thread> threads = new ArrayList<>(5);

    /** Deferred exception text */
    private static String deferredText;

    /** Deferred exception */
    private static Throwable deferredException;

    /**
     * Handles program initialization
     *
     * @param   args                Command-line arguments
     */
    public static void main(String[] args) {
        try {
            fileSeparator = System.getProperty("file.separator");
            lineSeparator = System.getProperty("line.separator");
            userHome = System.getProperty("user.home");
            osName = System.getProperty("os.name").toLowerCase();
            //
            // Process command-line options
            //
            dataPath = System.getProperty("bitcoin.datadir");
            if (dataPath == null) {
                if (osName.startsWith("win"))
                    dataPath = userHome+"\\Appdata\\Roaming\\BitcoinWallet";
                else if (osName.startsWith("linux"))
                    dataPath = userHome+"/.BitcoinWallet";
                else if (osName.startsWith("mac os"))
                    dataPath = userHome+"/Library/Application Support/BitcoinWallet";
                else
                    dataPath = userHome+"/BitcoinWallet";
            }
            //
            // Process command-line arguments
            //
            if (args.length != 0)
                processArguments(args);
            if (testNetwork)
                dataPath = dataPath+fileSeparator+"TestNet";
            //
            // Create the data directory if it doesn't exist
            //
            File dirFile = new File(dataPath);
            if (!dirFile.exists())
                dirFile.mkdirs();
            //
            // Initialize the logging properties from 'logging.properties'
            //
            File logFile = new File(dataPath+fileSeparator+"logging.properties");
            if (logFile.exists()) {
                FileInputStream inStream = new FileInputStream(logFile);
                LogManager.getLogManager().readConfiguration(inStream);
            }
            //
            // Use the brief logging format
            //
            BriefLogFormatter.init();
            //
            // Open the application lock file
            //
            lockFile = new RandomAccessFile(dataPath+fileSeparator+".lock", "rw");
            fileLock = lockFile.getChannel().tryLock();
            if (fileLock == null)
                throw new IllegalStateException("BitcoinWallet is already running");
            //
            // Process configuration file options
            //
            processConfig();
            if (testNetwork && peerAddresses == null)
                throw new IllegalArgumentException("You must specify at least one peer for the test network");
            //
            // Initialize the network parameters
            //
            String genesisName;
            if (testNetwork) {
                genesisName = "GenesisBlock/GenesisBlockTest.dat";
            } else {
                genesisName = "GenesisBlock/GenesisBlockProd.dat";
            }
            //
            // Load the genesis block
            //
            Class<?> mainClass = Class.forName("org.ScripterRon.BitcoinWallet.Main");
            try (InputStream classStream = mainClass.getClassLoader().getResourceAsStream(genesisName)) {
                if (classStream == null)
                    throw new IOException("Genesis block resource not found");
                Parameters.GENESIS_BLOCK_BYTES = new byte[classStream.available()];
                classStream.read(Parameters.GENESIS_BLOCK_BYTES);
            }
            //
            // Get the application build properties
            //
            try (InputStream classStream = mainClass.getClassLoader().getResourceAsStream("META-INF/application.properties")) {
                if (classStream == null)
                    throw new IllegalStateException("Application build properties not found");
                Properties applicationProperties = new Properties();
                applicationProperties.load(classStream);
                applicationID = applicationProperties.getProperty("application.id");
                applicationName = applicationProperties.getProperty("application.name");
                applicationVersion = applicationProperties.getProperty("application.version");
            }
            Parameters.SOFTWARE_NAME = String.format("%s:%s", applicationID, applicationVersion);
            log.info(String.format("%s Version %s", applicationName, applicationVersion));
            log.info(String.format("Application data path: '%s'", dataPath));
            //
            // Load the saved application properties
            //
            propFile = new File(dataPath+fileSeparator+"BitcoinWallet.properties");
            properties = new Properties();
            if (propFile.exists()) {
                try (FileInputStream in = new FileInputStream(propFile)) {
                    properties.load(in);
                }
            }
            //
            // Initialize the BitcoinCore library
            //
            NetParams.configure(testNetwork, Parameters.MIN_PROTOCOL_VERSION, Parameters.SOFTWARE_NAME, 0);
            //
            // Start our services on the GUI thread so we can display dialogs
            //
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            javax.swing.SwingUtilities.invokeLater(() -> startup());
        } catch (Exception exc) {
            logException("Exception during program initialization", exc);
        }
    }

    /**
     * Start our services
     */
    private static void startup() {
        try {
            //
            // Get the wallet passphrase if it is not specified in the application properties
            //
//            if (Parameters.passPhrase == null || Parameters.passPhrase.length() == 0) {
//                Parameters.passPhrase = JOptionPane.showInputDialog("Enter the wallet passphrase");
//                if (Parameters.passPhrase == null || Parameters.passPhrase.length() == 0)
//                    System.exit(0);
//            }
            //
            // Create the wallet
            //
            Parameters.wallet = new WalletSqlHw(dataPath);
            log.info("HwWallet object created");
            //
            // Connect the dongle and setup the Hardware wallet
            //
            if(!((WalletSqlHw)Parameters.wallet).hwWalletSetupDone()){
                log.info("HwWallet not initialized");
                String strpin = JOptionPane.showInputDialog("Setup - Enter the PIN code");
                String strublk = JOptionPane.showInputDialog("Setup - Enter the PUK code");
                if (strpin == null || strpin.length() == 0 || strublk == null || strublk.length() == 0)
                    System.exit(0);
                ((WalletSqlHw)Parameters.wallet).hwWalletSetup(strpin, strublk);
                log.info("HwWallet initialized!");
            }
            String strpin = JOptionPane.showInputDialog("Login - Enter the PIN code");
            if (strpin == null || strpin.length() == 0)
                System.exit(0);
            ((WalletSqlHw)Parameters.wallet).hwWalletVerifyPIN((byte)0x00, strpin);
            log.info("HwWallet verify PIN");
            //
            // recover authentikey and set the BIP32 seeed if necessary
            //
            if (!((WalletSqlHw)Parameters.wallet).hwWalletIsSeeded()){
                log.info("HwWallet seed not initialized");
                String strseed= JOptionPane.showInputDialog("Enter the BIP32 seed");
                if (strseed == null || strseed.length() == 0)
                    System.exit(0);
                ((WalletSqlHw)Parameters.wallet).hwWalletImportSeed(strseed);
                log.info("HwWallet seed initialized!");
            }
            log.info("HwWallet is seeded");
            //
            // Get the address and key lists
            //
            Parameters.addresses = Parameters.wallet.getAddressList();
            Parameters.keys = Parameters.wallet.getKeyList();
            //
            // Locate the change key and create it if we don't have one yet
            //
            for (ECKey key : Parameters.keys) {
                if (key.isChange()) {
                    Parameters.changeKey = key;
                    log.info("HwWallet recover change pubkey from db:"+key.getLabel()
                            +" pubkey:"+CardConnector.toString(key.getPubKey())
                            +" keypath:"+CardConnector.toString(((ECKeyHw)key).getKeypath()));
                    break;
                }
            }
            if (Parameters.changeKey == null) {
                log.info("HwWallet create changeKey");
                ECKey changeKey = new ECKeyHw(WalletSqlHw.changePath);
                changeKey.setLabel("<Change>");
                changeKey.setChange(true);
                Parameters.wallet.storeKey(changeKey);
                Parameters.changeKey = changeKey;
                Parameters.keys.add(changeKey);
            }
            //
            // Create our bloom filter
            //
            int elementCount = Parameters.keys.size()*2 + 15;
            BloomFilter filter = new BloomFilter(elementCount);
            Parameters.keys.stream().forEach((key) -> {
                filter.insert(key.getPubKey());
                filter.insert(key.getPubKeyHash());
            });
            Parameters.bloomFilter = filter;
            //
            // Create our inventory handler
            //
            Parameters.messageListener = new WalletMessageListener();
            //
            // Start the worker threads
            //
            // DatabaseListener - 1 thread
            // NetworkListener - 1 thread
            // MessageHandler - 1 thread
            //
            threadGroup = new ThreadGroup("Workers");

            Parameters.databaseHandler = new DatabaseHandler();
            Thread thread = new Thread(threadGroup, Parameters.databaseHandler);
            thread.start();
            threads.add(thread);

            Parameters.networkHandler = new NetworkHandler(peerAddresses);
            thread = new Thread(threadGroup, Parameters.networkHandler);
            thread.start();
            threads.add(thread);

            messageHandler = new MessageHandler();
            thread = new Thread(threadGroup, messageHandler);
            thread.start();
            threads.add(thread);
            //
            // Start the GUI
            //
            createAndShowGUI();
        } catch (KeyException exc) {
            log.error("The wallet passphrase is not correct", exc);
            JOptionPane.showMessageDialog(null, "The wallet passphrase is not correct",
                                          "Error", JOptionPane.ERROR_MESSAGE);
            shutdown();
        } catch (CardConnectorException ex) {
            log.error("CardConnectorException: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
            shutdown();
        }catch (ECException ex) {
            log.error("ECException: "+ex.getMessage(),ex);
            shutdown();
        } catch (Exception exc) {
            logException("Exception while starting wallet services", exc);
            shutdown();
        }
    }

    /**
     * Create and show our application GUI
     *
     * This method is invoked on the AWT event thread to avoid timing
     * problems with other window events
     */
    private static void createAndShowGUI() {
        //
        // Use the normal window decorations as defined by the look-and-feel
        // schema
        //
        JFrame.setDefaultLookAndFeelDecorated(true);
        //
        // Create the main application window
        //
        mainWindow = new MainWindow();
        //
        // Show the application window
        //
        mainWindow.pack();
        mainWindow.setVisible(true);
    }

    /**
     * Shutdown and exit
     */
    public static void shutdown() {

        //
        // Stop the network
        //
        Parameters.networkHandler.shutdown();
        Parameters.databaseHandler.shutdown();
        messageHandler.shutdown();
        //
        // Wait for threads to terminate
        //
        try {
            log.info("Waiting for worker threads to stop");
            for (Thread thread : threads)
                thread.join(2*60*1000);
            log.info("Worker threads have stopped");
        } catch (InterruptedException exc) {
            log.info("Interrupted while waiting for threads to stop");
        }
        //
        // Close the database
        //
        Parameters.wallet.close();
        //
        // Save the application properties
        //
        saveProperties();
        //
        // Close the application lock file
        //
        try {
            fileLock.release();
            lockFile.close();
        } catch (IOException exc) {
        }
        //
        // All done
        //
        System.exit(0);
    }

    /**
     * Save the application properties
     */
    public static void saveProperties() {
        try {
            try (FileOutputStream out = new FileOutputStream(propFile)) {
                properties.store(out, "BitcoinWallet Properties");
            }
        } catch (Exception exc) {
            Main.logException("Exception while saving application properties", exc);
        }
    }

    /**
     * Parses the command-line arguments
     *
     * @param       args            Command-line arguments
     */
    private static void processArguments(String[] args) throws UnknownHostException {
        //
        // PROD indicates we should use the production network
        // TEST indicates we should use the test network
        //
        if (args[0].equalsIgnoreCase("TEST")) {
            testNetwork = true;
        } else if (!args[0].equalsIgnoreCase("PROD")) {
            throw new IllegalArgumentException("Valid options are PROD and TEST");
        }
        if (args.length > 1)
            throw new IllegalArgumentException("Unrecognized command line parameter");
    }

    /**
     * Process the configuration file
     *
     * @throws      IllegalArgumentException    Invalid configuration option
     * @throws      IOException                 Unable to read configuration file
     * @throws      UnknownHostException        Invalid peer address specified
     */
    private static void processConfig() throws IOException, IllegalArgumentException, UnknownHostException {
        //
        // Use the defaults if there is no configuration file
        //
        File configFile = new File(dataPath+Main.fileSeparator+"BitcoinWallet.conf");
        if (!configFile.exists())
            return;
        //
        // Process the configuration file
        //
        List<PeerAddress> addressList = new ArrayList<>(5);
        try (BufferedReader in = new BufferedReader(new FileReader(configFile))) {
            String line;
            while ((line=in.readLine()) != null) {
                line = line.trim();
                if (line.length() == 0 || line.charAt(0) == '#')
                    continue;
                int sep = line.indexOf('=');
                if (sep < 1)
                    throw new IllegalArgumentException(String.format("Invalid configuration option: %s", line));
                String option = line.substring(0, sep).trim().toLowerCase();
                String value = line.substring(sep+1).trim();
                switch (option) {
                    case "connect":
                        PeerAddress addr = new PeerAddress(value);
                        addressList.add(addr);
                        break;
                    case "passphrase":
                        Parameters.passPhrase = value;
                        break;
                    default:
                        throw new IllegalArgumentException(String.format("Invalid configuration option: %s", line));
                }
            }
        }
        if (!addressList.isEmpty())
            peerAddresses = addressList.toArray(new PeerAddress[addressList.size()]);
    }

    /**
     * Convert a decimal string to a Satoshi BigInteger (1 Satoshi = 0.00000001 BTC)
     *
     * @param       value           String to be converted
     * @return                      BigInteger representation
     */
    public static BigInteger stringToSatoshi(String value) throws NumberFormatException {
        if (value == null)
            throw new IllegalArgumentException("No string value provided");
        if (value.isEmpty())
            return BigInteger.ZERO;
        BigDecimal decValue = new BigDecimal(value);
        return decValue.multiply(SATOSHI).toBigInteger();
    }

    /**
     * Convert from a Satoshi BigInteger (1 Satoshi = 0.00000001 BTC) to a formatted BTC decimal string.
     * We will keep at least 4 decimal places in the result.
     *
     * @param       value           Value to be converted
     * @return                      A formatted decimal string
     */
    public static String satoshiToString(BigInteger value) {
        //
        // Format the BTC amount
        //
        // BTC values are represented as integer values expressed in Satoshis (1 Satoshi = 0.00000001 BTC)
        //
        BigInteger bvalue = value;
        boolean negative = bvalue.compareTo(BigInteger.ZERO) < 0;
        if (negative)
            bvalue = bvalue.negate();
        //
        // Get the BTC amount as a formatted string with 8 decimal places
        //
        BigDecimal dvalue = new BigDecimal(bvalue, 8);
        String formatted = dvalue.toPlainString();
        //
        // Drop trailing zeroes beyond 4 decimal places
        //
        int decimalPoint = formatted.indexOf(".");
        int toDelete = 0;
        for (int i=formatted.length()-1; i>decimalPoint+4; i--) {
            if (formatted.charAt(i) == '0')
                toDelete++;
            else
                break;
        }
        String text = (negative?"-":"") + formatted.substring(0, formatted.length()-toDelete);
        return text;
    }

    /**
     * Display a dialog when an exception occurs.
     *
     * @param       text        Text message describing the cause of the exception
     * @param       exc         The Java exception object
     */
    public static void logException(String text, Throwable exc) {
        if (SwingUtilities.isEventDispatchThread()) {
            StringBuilder string = new StringBuilder(512);
            //
            // Display our error message
            //
            string.append("<html><b>");
            string.append(text);
            string.append("</b><br><br>");
            //
            // Display the exception object
            //
            string.append(exc.toString());
            string.append("<br>");
            //
            // Display the stack trace
            //
            StackTraceElement[] trace = exc.getStackTrace();
            int count = 0;
            for (StackTraceElement elem : trace) {
                string.append(elem.toString());
                string.append("<br>");
                if (++count == 25)
                    break;
            }
            string.append("</html>");
            JOptionPane.showMessageDialog(Main.mainWindow, string, "Error", JOptionPane.ERROR_MESSAGE);
        } else if (deferredException == null) {
            deferredText = text;
            deferredException = exc;
            try {
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    Main.logException(deferredText, deferredException);
                    deferredException = null;
                    deferredText = null;
                });
            } catch (Exception logexc) {
                log.error("Unable to log exception during program initialization");
            }
        }
    }

    /**
     * Dumps a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     */
    public static void dumpData(String text, byte[] data) {
        dumpData(text, data, 0, data.length);
    }

    /**
     * Dumps a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     * @param       length      Length to dump
     */
    public static void dumpData(String text, byte[] data, int length) {
        dumpData(text, data, 0, length);
    }

    /**
     * Dump a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     * @param       offset      Offset into array
     * @param       length      Data length
     */
    public static void dumpData(String text, byte[] data, int offset, int length) {
        StringBuilder outString = new StringBuilder(512);
        outString.append(text);
        outString.append("\n");
        for (int i=0; i<length; i++) {
            if (i%32 == 0)
                outString.append(String.format(" %14X  ", i));
            else if (i%4 == 0)
                outString.append(" ");
            outString.append(String.format("%02X", data[offset+i]));
            if (i%32 == 31)
                outString.append("\n");
        }
        if (length%32 != 0)
            outString.append("\n");
        log.info(outString.toString());
    }
}
