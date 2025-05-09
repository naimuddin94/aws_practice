/*
 * Title: E-commerce Backend
 * Description: A E-commerce backend system using express, mongoose
 * Author: Md Naim Uddin
 * Github: naimuddin94
 * Date: 03/05/2025
 *
 */

/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Application, NextFunction, Request, Response } from 'express';
import routes from './app/routes';
import { globalErrorHandler, notFound } from './app/utils';

const app: Application = express();

app.use(
  cors({
    credentials: true,
    origin: ['http://localhost:3000'],
  })
);
app.use(cookieParser());

// static files
app.use('/public', express.static('public'));

//parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/v1', routes);

//Testing
app.get('/', (req: Request, res: Response, next: NextFunction) => {
  res.send({ message: 'Express server is running :(' });
});

//global error handler
app.use(globalErrorHandler as unknown as express.ErrorRequestHandler);

//handle not found
app.use(notFound);

export default app;
