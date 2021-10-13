import './App.css';
import ButtonAppBar from './components/Appbar';
import Asymmetric from './components/Asymmetric';
import LoadImages from './components/ImageLoader';
// import images from './components/Images';
import { RegisterForm } from './components/RegisterForm';
import { Container, Typography, AppBar, CssBaseline, Toolbar } from '@mui/material'
import EnhancedEncryptionIcon from '@mui/icons-material/EnhancedEncryption';
import { makeStyles } from '@mui/styles';

const useStyles = makeStyles({
  container: {
    backgroundColor: 'gray',
    padding: 50
    // color: (props) => props.color,
  },
});

function App() {
  const classes = useStyles();

  return (
    <div className="App">
      <CssBaseline>
        <AppBar position='relative'>
          <Toolbar>
            <EnhancedEncryptionIcon/>
            <Typography variant='h6'>Cryptography</Typography>
          </Toolbar>
        </AppBar>

        <main>
          <div className={classes.container}>
            <Container maxWidth="sm">
              <Typography variant='h2' align='center' color='textPrimary' gutterBottom>
                Cryptography
              </Typography>
              <Typography variant='h6' align='center' color='textSecondary' paragraph>
                lorem ipsum dolor sit amet, consectetur lorem ipsum  lorem ur lorem ipsum lorem 
              </Typography>

            </Container>
          </div>
        </main>

      </CssBaseline>
    </div>
  );
}

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
