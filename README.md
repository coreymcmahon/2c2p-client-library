# 2C2P Client side encryption library

## Build

```
npm install
gulp
```

```
npm install
gulp --production
```

## Usage

```javascript
My2c2p.submitForm(false, function (token) {

  console.log('token', token);

}, function (errorCode, errorMessage) {

  alert('error!');

}, {
  cardnumber: "4111111111111111",
  cvv: "000", 
  month: "1",
  year: "2020"
});
```
