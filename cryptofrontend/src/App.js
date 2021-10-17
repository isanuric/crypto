// import ButtonAppBar from './components/Appbar';
// import Asymmetric from './components/Asymmetric';
// import LoadImages from './components/ImageLoader';
// import images from './components/Images';
// import { RegisterForm } from './components/RegisterForm';
// import { Container, Typography, CssBaseline } from "@mui/material";
// import { makeStyles } from "@mui/styles";
// import ListTest from "./components/ListTest";
// import Button from "@mui/material/Button";

import Appbar from "./components/Appbar";
import Content from "./components/Content";
import { ThemeProvider } from "@mui/material/styles";
import theme from "./theme";
import { Grid, Paper, Typography } from "@mui/material";
import CryptoCard from "./components/CryptoCard";

function App() {
  return (
    <ThemeProvider theme={theme}>
      <div className="App">
        {/* <Grid container direction="column"> */}
        <Appbar />

        <Grid container justify="center">
          <Grid item xs={false} sm={2} />
          <Grid item xs={12} sm={8}>
            <Content />
          </Grid>
          <Grid item xs={false} sm={2} />
        </Grid>

        {/* <Paper>
          <Grid
            container
            direction="row"
            justifyContent="space-evenly"
            alignItems="center"
            spacing={}
          >
            <CryptoCard />
            <CryptoCard />
            <CryptoCard />
          </Grid>
        </Paper> */}

        {/* </Grid> */}
      </div>
    </ThemeProvider>
  );
}

// const useStyles = makeStyles({
//   container: {
//     backgroundColor: "gray",
//     margin: 30,
//     padding: 50,
//     // color: (props) => props.color,
//   },
// });

// const listTest = [
//   {
//     name: "aaa AAA",
//     color: "black",
//   },
//   {
//     name: "bbb BBB",
//     color: "red",
//   },
//   {
//     name: "ccc CCC",
//     color: "yellow",
//   },
// ];

// function App() {
//   const classes = useStyles();

//   return (
//     <ThemeProvider theme={theme}>
//       <div className="App">
//         <CssBaseline>
//           <Appbar />

//           <main>
//             <div className={classes.container}>
//               <Container maxWidth="sm">
//                 <Typography
//                   variant="h2"
//                   align="center"
//                   color="textPrimary"
//                   gutterBottom
//                 >
//                   Cryptography
//                 </Typography>
//                 <Typography
//                   variant="h6"
//                   align="center"
//                   color="textSecondary"
//                   paragraph
//                 >
//                   lorem ipsum dolor sit amet, consectetur lorem ipsum lorem ur
//                   lorem ipsum lorem
//                 </Typography>
//                 <Button color="secondary">Save</Button>

//                 <ListTest theList={listTest} />
//               </Container>
//             </div>
//           </main>
//         </CssBaseline>
//       </div>
//     </ThemeProvider>
//   );
// }

// function App() {
//   return (
//     <div className="App">
//       <ButtonAppBar/>
//       <LoadImages images={images} interval="6000"/>
//       <Asymmetric/>
//       <RegisterForm/>
//     </div>
//   );
// }

export default App;
