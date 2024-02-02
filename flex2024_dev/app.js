const express = require("express");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cors = require("cors");
const path = require("path");
const bodyParser = require('body-parser')
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const fileUpload = require("express-fileupload");

const AppError = require("./utils/appError");
const writeLog = require("./utils/writeLog");

// Controllers


// New Routes


// Routes
const globalErrorHandler = require("./controllers/errorController");
const userRouter = require("./routes/userRoutes");
const employeeRouter = require("./routes/employeeRoutes");
const roleRouter = require("./routes/roleRoutes");
const departmentRouter = require("./routes/departmentRoutes");
const subsidiaryRouter = require("./routes/subsidiaryRoutes");
const locationRouter = require("./routes/locationRoutes");
const listRouter = require("./routes/listRoutes");
const classRouter = require("./routes/classRoutes");
const budgetRouter = require("./routes/budgetRoutes");
const accountTypeRouter = require("./routes/accountTypeRoutes");
const accountRouter = require("./routes/accountRoutes");
const journalEntryRouter = require("./routes/journalEntryRoutes");
const loginAuditRouter = require("./routes/loginAuditRoutes");
const itemRouter = require("./routes/itemRoutes");

const supplierRouter = require("./routes/supplierRoutes");
const purchaseOrderRouter = require("./routes/purchaseOrderRoutes");
const productReceiptRouter = require("./routes/productReceiptRoutes");
const glImpactRouter = require("./routes/glImpactRoutes");
const billRouter = require("./routes/billRoutes");
const vendorRouter = require("./routes/vendorRoutes");
const productRouter = require("./routes/productRoutes");
const generalLedgerRouter = require("./routes/generalLedgerRoutes");
const customerRouter = require("./routes/customerRoutes");
const salesOrderRouter = require("./routes/salesOrderRoutes");
const productDeliveryRouter = require("./routes/productDeliveryRoutes");
const invoiceRouter = require("./routes/invoiceRoutes");
const paymentRouter = require("./routes/paymentRoutes");
const invoicePaymentRouter = require("./routes/invoicePaymentRoutes");
const billPaymentRouter = require("./routes/billPaymentRoutes");
const unitsRouter = require("./routes/unitsRoutes");
const gstRatesRouter = require("./routes/gstRatesRoutes");
const expenseRouter = require("./routes/expenseRoutes");
const jobPositionRouter = require("./routes/jobPositionRoutes");
const workCenterRouter = require("./routes/workCenterRoutes");
const bomRouter = require("./routes/bomRoutes");
const jobOrderRouter = require("./routes/jobOrderRoutes");
const itemCategoryRoute = require("./routes/itemCategoryRoute");
const priceChartUploadRoute = require("./routes/priceChartUploadRoutes");
const sizeListRoute = require("./routes/sizeListRoutes");
const permissionRoute = require("./routes/permissionRoutes");
const rolesRoute = require("./routes/roleRoutes");
const cashSaleRoute = require("./routes/cashSaleRoutes");
const companyRoute = require("./routes/companyRoutes");

const appCenterRoute = require("./routes/appCenterRoutes");
const customDocumentTypeRoute = require("./routes/customDocumentTypeRoutes");
const appNavigationCenterRoute = require("./routes/appNavigationCenterRoutes");
const documentMappingRoutes = require("./routes/documentMappingRoutes");
const netsuiteSyncRoutes = require("./routes/netsuiteSyncRoutes");
const schemaRoutes = require("./routes/schemaRoutes");
const blogRoutes = require("./routes/blogRoutes");
const customListRoutes = require("./routes/customListRoutes");
const pmcliteAccessRoutes = require("./routes/pmcliteAccessRoutes");

const encryptionRoute = require("./routes/encryptionRoutes");
const OcrRoute = require("./routes/OcrRoutes");
const InventoryTrackRoute = require("./routes/inventoryTrackRoutes");
const ModelRoute = require("./routes/modelRoutes");
const ManufacturerPaysRoute = require("./routes/manufacturerPaysRoutes");
const ManufacturerRoute = require("./routes/manufacturerRoutes");
const RVStatusRoute = require("./routes/rvStatusRoutes");

// const tourRouter = require('./routes/tourRoutes');
// const syncRouter = require('./routes/syncRoutes');

var app = express();
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

if (process.env.NODE_ENV === "development") {
  console.log("devlopment");
}

// GLOBAL MIDDLEWARE STACK
app.enable("trust proxy");
// SET SECURITY HTTP HEADERS
// Its best to used helmet function earlier in the middleware stack, so that ths header are really sure to added
const corsOptions = {
  origin: '*',
  credentials: true,            //access-control-allow-credentials:true
  optionSuccessStatus: 200,
}
app.use(helmet());
app.use(cors());
app.use(function (req, res, next) {
  if (req.method === 'OPTIONS') {
    console.log('!OPTIONS');
    writeLog("!OPTIONS")
    var headers = {};

    headers["Access-Control-Allow-Origin"] = "*";
    headers["Access-Control-Allow-Methods"] = "POST, GET, PUT, DELETE, OPTIONS";
    headers["Access-Control-Allow-Credentials"] = false;
    headers["Access-Control-Max-Age"] = '86400'; // 24 hours
    headers["Access-Control-Allow-Headers"] = "X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept";
    res.writeHead(200, headers);
    res.end();
  }

  next();
});
// LIMIT REQUEST FROM SAME API - API LIMITING USING EXPRESS PACKAGE
// This limiter function will prevent from the DENIAL-OF-SERVICE && BRUTE FORCE ATTACKS
// It will allow 100 request from the same IP in 1 hour. And if that limit is crossed by certain Ip they will get by an error message
const limiter = rateLimit({
  max: 10000,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests from this IP, please try again in an hour!",
});

// This will effects all routes which basically starts with /api
app.use("/api", limiter);

// BODY PARSER, READING DATA FROM THE BODY INTO req.body
// app.use(express.json({ limit: "60mb" }));
// app.use(express.urlencoded({ limit: "60mb" }));

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ limit: "1536mb", extended: true }))

// parse application/json
app.use(bodyParser.json({ limit: "1536mb" }))
app.use(cookieParser());
app.use(fileUpload());

// DATA SANITIZATION AGAINST NoSQL QUERY INJECTION
app.use(mongoSanitize());

// DATA SANITIZATION AGAINST XSS
// This will clean any malicious html code with some javascript code
app.use(xss());

// PREVENT PARAMETER POLLUTION
// If multipe params with same key requested then it will take only the last one
app.use(
  hpp({
    whitelist: [
      "duration",
      "ratingQuantity",
      "ratingAverage",
      "maxGroupSize",
      "difficulty",
      "price",
    ],
  })
);

app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "staging")));

// TEST MIDDLEWARE
app.use((req, res, next) => {
  console.log("Incoming Data Into Server");
  // console.log(req);
  // console.log(req.ip);
  // console.log(req.method);
  // console.log(req.rawHeaders[11]);

  req.requestTime = new Date().toISOString();
  next();
});

// New Routing
// New Routes
const inventoryAdjustmentRouter = require("./modules/inventoryAdjustment/inventoryAdjustmentRoutes");
app.use("/api/v1/inventoryAdjustment", inventoryAdjustmentRouter);



// Routing >>>
app.use("/api/v1/user", userRouter);
app.use("/api/v1/employee", employeeRouter);
app.use("/api/v1/role", roleRouter);
app.use("/api/v1/department", departmentRouter);
app.use("/api/v1/subsidiary", subsidiaryRouter);
app.use("/api/v1/location", locationRouter);
app.use("/api/v1/list", listRouter);
app.use("/api/v1/class", classRouter);
app.use("/api/v1/budget", budgetRouter);
app.use("/api/v1/accountType", accountTypeRouter);
app.use("/api/v1/account", accountRouter);
app.use("/api/v1/journalEntry", journalEntryRouter);
app.use("/api/v1/loginAudit", loginAuditRouter);
app.use("/api/v1/item", itemRouter);
app.use("/api/v1/supplier", supplierRouter);
app.use("/api/v1/purchaseOrder", purchaseOrderRouter);
app.use("/api/v1/productReceipt", productReceiptRouter);
app.use("/api/v1/glImpact", glImpactRouter);
app.use("/api/v1/bill", billRouter);
app.use("/api/v1/vendor", vendorRouter);
app.use("/api/v1/product", productRouter);
app.use("/api/v1/generalLedger", generalLedgerRouter);
app.use("/api/v1/customer", customerRouter);
app.use("/api/v1/salesOrder", salesOrderRouter);
app.use("/api/v1/productDelivery", productDeliveryRouter);
app.use("/api/v1/invoice", invoiceRouter);
app.use("/api/v1/payment", paymentRouter);
app.use("/api/v1/invoicePayment", invoicePaymentRouter);
app.use("/api/v1/billPayment", billPaymentRouter);
app.use("/api/v1/uom", unitsRouter);
app.use("/api/v1/gstRates", gstRatesRouter);
app.use("/api/v1/expense", expenseRouter);
app.use("/api/v1/jobPosition", jobPositionRouter);
app.use("/api/v1/workCenter", workCenterRouter);
app.use("/api/v1/bom", bomRouter);
app.use("/api/v1/jobOrder", jobOrderRouter);
app.use("/api/v1/itemCategory", itemCategoryRoute);
app.use("/api/v1/priceChartUpload", priceChartUploadRoute);
app.use("/api/v1/sizeList", sizeListRoute);
app.use("/api/v1/permission", permissionRoute);
app.use("/api/v1/role", rolesRoute);
app.use("/api/v1/cashSale", cashSaleRoute);
app.use("/api/v1/company", companyRoute);

app.use("/api/v1/appCenter", appCenterRoute);
app.use("/api/v1/customDocumentType", customDocumentTypeRoute);
app.use("/api/v1/appNavigationCenter", appNavigationCenterRoute);
app.use("/api/v1/documentMapping", documentMappingRoutes);
app.use("/api/v1/netsuiteSync", netsuiteSyncRoutes);
app.use("/api/v1/schema", schemaRoutes);
app.use("/api/v1/blog", blogRoutes);
app.use("/api/v1/customList", customListRoutes);
app.use("/api/v1/pmcliteaccess", pmcliteAccessRoutes)

app.use("/api/v1/secure", encryptionRoute);
app.use("/api/v1/ocr", OcrRoute);
app.use("/api/v1/inventoryTrack", InventoryTrackRoute);
app.use("/api/v1/model", ModelRoute);
app.use("/api/v1/manufacturerPays", ManufacturerPaysRoute);
app.use("/api/v1/manufacturer", ManufacturerRoute);
app.use("/api/v1/status", RVStatusRoute);



// app.use('/api/v1/tour', tourRouter);
// app.use('/api/v1/sync', syncRouter);

// DEFAULT ROUTE
app.all("*", (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server.`, 404));
});

// GLOBAL ERROR HANDLING
app.use(globalErrorHandler);

module.exports = app;
