import Item from "../models/itemModel.js";
import axios from "axios";
import dotenv from 'dotenv'
import connectDB from '../config/db.js'
dotenv.config();
connectDB();
const importItems = async () => {
  const dataFromServer = await axios.get("https://dummyjson.com/products?limit=100", {
    headers: { Accept: "application/json", "Accept-Encoding": "identity" },
    params: { trophies: true },
  });
  const itemsFromServer = dataFromServer.data;

  const itemsArray=[]

  itemsFromServer.products.map(serverItem=>{
    const item={
        name:serverItem.title,
        description:serverItem.description? serverItem.description: "",
        category: serverItem.category,
        brand:serverItem.brand,
        price: serverItem.price,
        rating: null,
        stock:serverItem.stock,
        image:serverItem.thumbnail
    }
    itemsArray.push(item)
  })
try{
    console.log(itemsArray[0])
  await Item.insertMany(itemsArray)
  console.log("Items imported!");
}catch(error){
    console.log(`${error}`)
    process.exit(1);
}
  process.exit(0);

};

const destroyItems = async () => {
  try {
    await Item.deleteMany();

    console.log("Items Deleted!");
    process.exit(0);
  } catch (e) {
    console.log(e);
    process.exit(1);
  }
};

if (process.argv[2] === "-d") {
  destroyItems();
} else if (process.argv[2] == "-s") {
  importItems();
}
