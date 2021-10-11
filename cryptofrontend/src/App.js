import './App.css';
import ButtonAppBar from './components/Appbar';
import Asymmetric from './components/Asymmetric';
import LoadImages from './components/ImageLoader';
import images from './components/Images';
import { RegisterForm } from './components/RegisterForm';

function App() {
  return (
    <div className="App">
      <ButtonAppBar/>
      <LoadImages images={images} interval="6000"/>
      <Asymmetric/>
      <RegisterForm/>
    </div>
  );
}

export default App;
