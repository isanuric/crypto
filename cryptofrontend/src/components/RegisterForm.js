import { Paper } from '@mui/material';
import React from 'react';

export class RegisterForm extends React.Component {

    paperStyle={padding:'50px 20px', width:500, margin:'20px auto'}

    constructor(props) {
        super(props);
        this.state = {value: ''};
    
        this.handleChange = this.handleChange.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
        this.handleChangeWeekDay = this.handleChangeWeekDay.bind(this);
      }
    
      handleChange(event) {
          // event.target zeigt auf html element (hier text box)
          // event.target.value zeigt auf value von html element (hier value in text box)
          console.log(event.target.value);
          
          // value is this.state.value. See lines 10 and 38
          this.setState({
                value: event.target.value,
                weekDay: 'Monday'
           });
      }

      handleChangeWeekDay(event) {
          console.log(event.target);

          this.setState ({
            weekday: event.target.value
          })
      }
    
      handleSubmit(event) {
        alert('A name was submitted: ' + this.state.value);
        event.preventDefault();
      }
    
      render() {
        return (
          <Paper elevation={3} style={this.paperStyle}>
              <form onSubmit={this.handleSubmit}>
                <label>
                Name:
                <input type="text" value={this.state.value} onChange={this.handleChange} />
                </label>
                <input type="submit" value="Submit" />
            </form>

            <br></br>
            <select 
            value={this.state.weekday} onChange={this.handleChangeWeekDay}>
                <option value='AA'>1</option>
                <option value="BB">2</option>
                <option value='CC'>3</option>
                <option>4</option>
                <option>5</option>
                <option>6</option>
                <option>7</option>
            </select>
          </Paper>

        );
      }
    }