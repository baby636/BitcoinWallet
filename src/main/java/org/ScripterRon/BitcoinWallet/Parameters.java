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
import org.ScripterRon.BitcoinCore.*;

import java.math.BigInteger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

/**
 * Global parameters for BitcoinWallet
 */
public class Parameters {

    /** Default network port */
    public static final int DEFAULT_PORT = 8333;

    /** Software identifier */
    public static String SOFTWARE_NAME = "/BitcoinWallet:1.3/";

    /** Genesis block bytes */
    public static byte[] GENESIS_BLOCK_BYTES;

    /** Minimum transaction fee */
    public static final BigInteger MIN_TX_FEE = new BigInteger("10000", 10);

    /** Dust transaction value */
    public static final BigInteger DUST_TRANSACTION = new BigInteger("5460", 10);

    /** Maximum ban score before a peer is disconnected */
    public static final int MAX_BAN_SCORE = 100;

    /** Coinbase transaction maturity */
    public static final int COINBASE_MATURITY = 120;

    /** Transaction maturity */
    public static final int TRANSACTION_CONFIRMED = 6;

    /** Short-term lock object */
    public static final Object lock = new Object();

    /** Message handler queue */
    public static final ArrayBlockingQueue<Message> messageQueue = new ArrayBlockingQueue<>(50);

    /** Database handler queue */
    public static final ArrayBlockingQueue<Object> databaseQueue = new ArrayBlockingQueue<>(50);

    /** Peer addresses */
    public static final List<PeerAddress> peerAddresses = new ArrayList<>(500);

    /** Peer address map */
    public static final Map<PeerAddress, PeerAddress> peerMap = new HashMap<>(250);

    /** Completed messages */
    public static final List<Message> completedMessages = new ArrayList<>(50);

    /** List of peer requests that are waiting to be sent */
    public static final List<PeerRequest> pendingRequests = new ArrayList<>(50);

    /** List of peer requests that are waiting for a response */
    public static final List<PeerRequest> processedRequests = new ArrayList<>(50);

    /** Network handler */
    public static NetworkHandler networkHandler;

    /** Database handler */
    public static DatabaseHandler databaseHandler;
    
    /** Inventory handler */
    public static InventoryHandler inventoryHandler;

    /** Wallet database */
    public static Wallet wallet;

    /** Bloom filter */
    public static BloomFilter bloomFilter;

    /** Key list */
    public static List<ECKey> keys;

    /** Change key */
    public static ECKey changeKey;

    /** Address list */
    public static List<Address> addresses;

    /** Network chain height */
    public static int networkChainHeight;

    /** Wallet passphrase */
    public static String passPhrase;
}