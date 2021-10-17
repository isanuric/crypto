import { Grid } from "@mui/material";
import React, { Component } from "react";
import CryptoCard from "./CryptoCard";
import Constants from "./Constants";

export default class Content extends Component {
  getCardsData = (data) => {
    return (
      <Grid item xs={12} sm={4}>
        <CryptoCard {...data} />
      </Grid>
    );
  };

  render() {
    return (
      <Grid container spacing={2}>
        {Constants.map((data) => this.getCardsData(data))}
      </Grid>
    );
  }
}
