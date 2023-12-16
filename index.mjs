import express from "express";
import fetch from "node-fetch";
import cors from "cors";
const app = express();
const port = 3000;
app.use(cors());

app.use(express.json());
import { MongoClient, ServerApiVersion } from "mongodb";
const uri = "mongodb+srv://secureAdmin:5WBcGZGrpIyVui9f@cluster0.vw1cwl2.mongodb.net/?retryWrites=true&w=majority";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function setupMongoDB() {
  try {
    await client.connect(); // Connect to the MongoDB database
    console.log("Connected to MongoDB");
    return client; // Return the connected client
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    throw error;
  }
}

app.get('/phishData', async (req, res) => {
  try {
    const connectedClient = await setupMongoDB();
    const phishingCollection = connectedClient
      .db("maliciousDB")
      .collection("phishingSites");
    const result = await phishingCollection.find().toArray();
    res.send(result);
  } catch (error) {
    console.error("Error while processing the request:", error);
    res.status(500).send("Internal Server Error");
  }
});
app.get("/check-safety", async (req, res) => {
  try {
    const { apiKey, url } = req.query;

    // Connect to MongoDB and obtain the connected client
    const connectedClient = await setupMongoDB();
    
    // Use the connected client for database operations
    const phishingCollection = connectedClient
      .db("maliciousDB")
      .collection("phishingSites");

    const response = await fetch(
      `https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${url}`
    );
 
    const priceFound = extractPrices(url);

    // Define the existingSite variable outside of try and catch blocks
    let existingSite;

    if (response.ok) {
      const data = await response.json();
      console.log(url)
      // Check if the URL is malicious
      if (data.positives !== 0) {
        const urlMappings = [
          { pattern: /amazon/i, mainLink: "https://www.amazon.com/", title: "Amazon" },
          { pattern: /apple/i, mainLink: "https://www.apple.com/", title: "Apple" },
          { pattern: /american/i, mainLink: "https://www.americanexpress.com/", title: "American Express" },
          { pattern: /aeon/i, mainLink: "https://aeon.co/", title: "AEON" },
          { pattern: /adobe/i, mainLink: "https://www.adobe.com/", title: "Adobe" },
          { pattern: /alibaba/i, mainLink: "https://www.alibaba.com/", title: "Alibaba" },
          { pattern: /allegro/i, mainLink: "https://allegro.pl/", title: "Allegro" },
          { pattern: /bank/i, mainLink: "Banks", title: "Banks" },
          { pattern: /barclays/i, mainLink: "https://www.barclays.co.uk/", title: "Barclays" },
          { pattern: /bt/i, mainLink: "https://www.bt.com/", title: "BT" },
          { pattern: /binance/i, mainLink: "https://www.binance.com/en", title: "Binance" },
          { pattern: /bitfin/i, mainLink: "https://www.bitfinex.com/", title:  "Bitfinex" },
          { pattern: /blockchain/i, mainLink: "https://www.blockchain.com/", title: "Blockchain" },
          { pattern: /cahoot/i, mainLink: "https://www.cahoot.com/", title: "Cahoot" },
          { pattern: /career/i, mainLink: "https://www.careerbuilder.com/", title: "Career Builder" },
          { pattern: /century/i, mainLink: "https://www.centurylink.com/", title: "CenturyLink" },
          { pattern: /coinbase/i, mainLink: "https://www.coinbase.com/", title: "Coinbase" },
          { pattern: /compass/i, mainLink: "https://www.compass.com/", title: "Compass" },
          { pattern: /craigs/i, mainLink: "https://www.craigslist.org/", title: "Craigslist" },
          { pattern: /delta/i, mainLink: "https://www.delta.com/apac/en", title: "Delta" },
          { pattern: /dhl/i, mainLink: "https://www.dhl.com/us-en/home.html", title: "DHL" },
          { pattern: /dropbox/i, mainLink: "https://www.dropbox.com/", title: "Dropbox" },
          { pattern: /ebay/i, mainLink: "https://www.ebay.com/", title: "Ebay" },
          { pattern: /(facebook|fb)/i, mainLink: "https://www.facebook.com/", title: "Facebook" },
          { pattern: /google/i, mainLink: "https://www.google.com/", title: "Google" },
          { pattern: /github/i, mainLink: "https://www.github.com/", title: "Github" },
          { pattern: /guildwars/i, mainLink: "https://www.guildwars2.com/en/", title: "Guildwars" },
          { pattern: /(hotmail|outlook)/i, mainLink: "https://outlook.live.com/mail/", title: "Hotmail" },
          { pattern: /idex/i, mainLink: "https://www.idexcorp.com/", title: "Idex Corp" },
          { pattern: /insta/i, mainLink: "https://www.instagram.com/", title: "Instagram" },
          { pattern: /linked/i, mainLink: "https://www.linkedin.com/", title: "LinkedIn" },
          { pattern: /masterc/i, mainLink: "https://www.mastercard.com/global/en/personal/find-card-products.html", title: "MasterCard" },
          { pattern: /microsoft/i, mainLink: "https://www.microsoft.com/en-us/", title: "Microsoft" },
          { pattern: /myether/i, mainLink: "https://www.myetherwallet.com/", title: "Myether Wallet" },
          { pattern: /myspace/i, mainLink: "https://myspace.com/", title: "MySpace" },
          { pattern: /netflix/i, mainLink: "https://netflix.com/", title: "Netflix" },
          { pattern: /paypal/i, mainLink: "https://paypal.com/", title: "Paypal" },
          { pattern: /rakuten/i, mainLink: "https://rakuten.com/", title: "Rakuten" },
          { pattern: /revolut/i, mainLink: "https://revolut.com/", title: "Revolut" },
          { pattern: /santander/i, mainLink: "https://www.santander.co.uk/", title: "Santander" },
          { pattern: /skype/i, mainLink: "https://www.skype.com/en/", title: "Skype" },
          { pattern: /steam/i, mainLink: "https://store.steampowered.com/", title: "Steam" },
          { pattern: /tagged/i, mainLink: "https://www.tagged.com/", title: "Tagged" },
          { pattern: /(twit|tweet)/i, mainLink: "https://www.twitter.com", title: "Twitter" },
          { pattern: /uber/i, mainLink: "https://www.uber.com", title: "Uber" },
          { pattern: /visa/i, mainLink: "https://www.usa.visa.com", title: "Visa" },
          { pattern: /voda/i, mainLink: "https://www.vodafone.com/", title: "Vodafone" },
          { pattern: /walm/i, mainLink: "https://www.walmart.com/", title: "Walmart" },
          { pattern: /western/i, mainLink: "https://www.westerunion.com/", title: "Western Union" },
          { pattern: /wetrans/i, mainLink: "https://www.wetransfer.com/", title: "WeTransfer" },
          { pattern: /whats/i, mainLink: "https://www.whatsapp.com/", title: "Whatsapp" },
          { pattern: /yaho/i, mainLink: "https://www.yahoo.com/", title: "Yahoo" },
          // Add more URL patterns here
        ];
        let mainLink, title;
        for (const mapping of urlMappings) {
          if (mapping.pattern.test(url)) {
            mainLink = mapping.mainLink;
            title = mapping.title;
            break; // Exit the loop when a match is found
          }
        }
        console.log(mainLink);
        // Determine the mainLink based on the URL
        if (mainLink) {
          try {
            const currentDate = new Date(); // Get the current date
            existingSite = await phishingCollection.findOne({ mainLink });
            if (existingSite) {
              const { phishingLinks } = existingSite;
              if (!phishingLinks.some(linkObj => linkObj.url === url)) {
                const newLinkObj = { url, title, Date: currentDate }; // Add the title and date
                if (priceFound) {
                  newLinkObj.price = priceFound;
                }
                await phishingCollection.updateOne(
                  { _id: existingSite._id },
                  { $push: { phishingLinks: newLinkObj } }
                );
              }
            } else {
              // If the mainLink is not found in the database, create a new entry
              const newSite = {
                mainLink,
                title, // Add the title
                phishingLinks: [
                  {
                    url,
                    title,
                    Date: currentDate, // Add the title and date
                    ...(priceFound && { price: priceFound }), // Conditionally add the price
                  },
                ],
              };
              await phishingCollection.insertOne(newSite);
              existingSite = { mainLink };
            }
          } catch (error) {
            console.error("Error while updating the database:", error);
          }
        }
      }
      if (existingSite) {
        res.json({ data, mainLink: existingSite.mainLink });
      } else {
        res.json({ data, mainLink: null });
      }
    } else {
      console.error("Error with VirusTotal API response. Status:", response.status);
      const responseText = await response.text(); // Get the response text for debugging
      console.error("Response text:", responseText);
      res.status(response.status).json({ error: "VirusTotal API request failed" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
function extractPrices(url) {
  const pricePattern = /\$\d+/g;
  const matches = url.match(pricePattern);
  if (matches) {
    const prices = matches.map(match => match.substring(1));
    const priceString = prices.join(", ");
    return priceString;
  } else {
    return "0";
  }
}
// Send a ping to confirm a successful connection
app.get("/", (req, res) => {
  res.send("Secure-link server is running");
});

async function startServer() {
  try {
    await setupMongoDB(); // Connect to MongoDB before starting the server

    // Start the Express server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  } catch (error) {
    console.error("Error starting the server:", error);
  }
}

startServer(); // Start the server and MongoDB connection
