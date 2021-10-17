import React, { Component } from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

export default class ListTest extends Component {
    render() {
        console.log(this.props.theList)
        const names = this.props.theList.map((element, index) => {
            const nameKey = `name-${index}`;
            return (
                <tr key={nameKey}>
                    <td>{element.name}</td>
                    <td >{element.color}</td>
                </tr>
            );
        });

        return (
            // <table>
            //     <thead>
            //         <tr>
            //             <th>Name</th>
            //             <th>Color</th>
            //         </tr>
            //     </thead>
            //     <tbody>
            //         {names}
            //     </tbody>
            // </table>
            <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="simple table">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Color</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                  {names}                 
              </TableBody>
            </Table>
          </TableContainer>

            
        );
    }
}
