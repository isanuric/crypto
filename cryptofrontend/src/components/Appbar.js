import * as React from "react";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import EnhancedEncryptionIcon from "@mui/icons-material/EnhancedEncryption";
import { makeStyles } from "@mui/styles";

const useStyles = makeStyles(() => ({
  typographyStyle: {
    flex: 1,
    variant: "h6",
  },
}));

export default function ButtonAppBar() {
  const classes = useStyles();
  return (
    <AppBar position="static">
      <Toolbar>
        <Typography className={classes.typographyStyle}>
          Cryptography
        </Typography>
        <EnhancedEncryptionIcon />
      </Toolbar>
    </AppBar>
  );
}
