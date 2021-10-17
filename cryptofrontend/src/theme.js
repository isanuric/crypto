import { createTheme } from "@mui/material/styles";
import purple from "@mui/material/colors/purple";
import green from "@mui/material/colors/green";

const theme = createTheme({
  palette: {
    primary: purple,
    secondary: green,
  },
  status: {
    danger: "orange",
  },
});

export default theme;
