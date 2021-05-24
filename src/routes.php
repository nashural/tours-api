<?php

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;
use \Firebase\JWT\JWT;

function withCORSHeaders(Response $resp) {
    return $resp
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', implode(',', ['X-Requested-With', 'Content-Type', 'Accept', 'Origin', 'Authorization']));
}

function splitCoordinates($coordinatesString) {
    $coordinatesStrings = explode(',', $coordinatesString);
    return [
        floatval($coordinatesStrings[0]),
        floatval($coordinatesStrings[1])
    ];
}

function parseToken($container, $req) {
    $authorizationHeader = $req->getHeader('Authorization')[0];
    $tokenString = substr($authorizationHeader, strlen("Bearer "));
    return JWT::decode($tokenString, $container->get('jwt_key'), array('HS256'));
}

return function (App $app) {
    $container = $app->getContainer();

    // OPTIONS

    $app->options('/auth/login', function (Request $req, Response $resp, array $args) use ($container) {
        return withCORSHeaders($resp)
            ->withHeader('Access-Control-Allow-Methods', implode(',', ['OPTIONS', 'POST']))
            ->withStatus(200);
    });

    $app->options('/auth/refresh_token', function (Request $req, Response $resp, array $args) use ($container) {
        return withCORSHeaders($resp)
            ->withHeader('Access-Control-Allow-Methods', implode(',', ['OPTIONS', 'POST']))
            ->withStatus(200);
    });

    $app->options('/guides', function (Request $req, Response $resp, array $args) use ($container) {
        return withCORSHeaders($resp)
            ->withHeader('Access-Control-Allow-Methods', implode(',', ['OPTIONS', 'GET', 'POST']))
            ->withStatus(200);
    });

    $app->options('/guides/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        return withCORSHeaders($resp)
            ->withHeader('Access-Control-Allow-Methods', implode(',', ['OPTIONS', 'GET', 'POST']))
            ->withStatus(200);
    });

    $app->options('/tours', function (Request $req, Response $resp, array $args) use ($container) {
        return withCORSHeaders($resp)
            ->withHeader('Access-Control-Allow-Methods', implode(',', ['OPTIONS', 'GET', 'POST']))
            ->withStatus(200);
    });

    $app->options('/tours/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        return withCORSHeaders($resp)
            ->withHeader('Access-Control-Allow-Methods', implode(',', ['OPTIONS', 'GET', 'POST', 'DELETE']))
            ->withStatus(200);
    });

    // AUTH

    $app->post('/auth/login', function (Request $req, Response $resp, array $args) use ($container) {
        $body = $req->getParsedBody();
        $email = $body['email'];
        $password = $body['password'];
        $user = $container->get('db')->table('users')->where('email', '=', $email)->first();
        if ($user) {
            $success = password_verify($password, $user->password_hash);
            if ($success) {
                $accessToken = JWT::encode([
                    'sub' => $user->id,
                    'iss' => $req->getUri()->getBaseUrl(),
                    'aud' => $req->getUri()->getBaseUrl(),
                    'iat' => time(),
                    'exp' => time() + (60 * 60) // + 1 час
                ], $container->get('jwt_key'));
                $refreshToken = JWT::encode([
                    'sub' => $user->id,
                    'iss' => $req->getUri()->getBaseUrl(),
                    'aud' => $req->getUri()->getBaseUrl(),
                    'iat' => time(),
                    'exp' => time() + (24 * 60 * 60) // + 1 день
                ], $container->get('jwt_key'));

                $container->get('db')->table('users')->where('id', '=', $user->id)->update([
                    'refresh_token' => $refreshToken
                ]);

                return withCORSHeaders($resp)->withJson([
                    'accessToken' => $accessToken,
                    'refreshToken' => $refreshToken
                ]);
            } else {
                return withCORSHeaders($resp)->withJson([
                    'errors' => [
                        [
                            'id' => $container->get('nanoid')->generateId(),
                            'code' => 'password-mismatch',
                            'title' => 'Пароль не подходит'
                        ]
                    ]
                ]);
            }
        } else {
            return withCORSHeaders($resp)->withJson([
                'errors' => [
                    [
                        'id' => $container->get('nanoid')->generateId(),
                        'code' => 'user-not-found',
                        'title' => 'Такой пользователь не найден'
                    ]
                ]
            ]);
        }
    });

    $app->post('/auth/register', function (Request $req, Response $resp, array $args) use ($container) {
        $body = $req->getParsedBody();
        $email = $body['email'];
        $user = $container->get('db')->table('users')->where('email', '=', $email)->first();
        if ($user) {
            return withCORSHeaders($resp)->withJson([
                'errors' => [
                    [
                        'id' => $container->get('nanoid')->generateId(),
                        'code' => 'email-in-use',
                        'title' => 'Емейл уже используется другим пользователем'
                    ]
                ]
            ]);
        } else {
            $password = $body['password'];
            $password_hash = password_hash($password, PASSWORD_BCRYPT);
            $container->get('db')->table('users')->insert([
                'id' => $container->get('nanoid')->generateId(),
                'email' => $email,
                'password_hash' => $password_hash
            ]);
            return withCORSHeaders($resp)->withJson([
                'success' => true
            ]);
        }        
    });

    $app->post('/auth/refresh_token', function (Request $req, Response $resp, array $args) use ($container) {
        $body = $req->getParsedBody();
        $refresh_token = $body['refreshToken'];
        $parsed_token = JWT::decode($refresh_token, $container->get('jwt_key'), array('HS256'));
        if ($parsed_token->exp > time()) {
            $user = $container->get('db')->table('users')->where('id', '=', $parsed_token->sub)->first();
            if ($user) {
                if ($user->refresh_token === $refresh_token) {
                    $new_access_token = JWT::encode([
                        'sub' => $user->id,
                        'iss' => $req->getUri()->getBaseUrl(),
                        'aud' => $req->getUri()->getBaseUrl(),
                        'iat' => time(),
                        'exp' => time() + (60 * 60) // + 1 час
                    ], $container->get('jwt_key'));
                    return withCORSHeaders($resp)->withJson([
                        'accessToken' => $new_access_token
                    ]);
                } else {
                    return withCORSHeaders($resp)->withJson([
                        'errors' => [
                            [
                                'id' => $container->get('nanoid')->generateId(),
                                'code' => 'token-mismatch',
                                'title' => 'Токен не совпадает'
                            ]
                        ]
                    ]);
                }
            } else {
                return withCORSHeaders($resp)->withJson([
                    'errors' => [
                        [
                            'id' => $container->get('nanoid')->generateId(),
                            'code' => 'user-not-found',
                            'title' => 'Пользователь не найден'
                        ]
                    ]
                ]);
            }
        } else {
            return withCORSHeaders($resp)->withJson([
                'errors' => [
                    [
                        'id' => $container->get('nanoid')->generateId(),
                        'code' => 'token-expired',
                        'title' => 'Токен протух'
                    ]
                ]
            ]);
        }
    });

    // GUIDES

    $app->get('/guides', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $guides = $container->get('db')->table('guides')->where('author', '=', $token->sub)->get();
        return withCORSHeaders($resp)->withJson($guides);
    });

    $app->get('/guides/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $id = $args['id'];
        $guide = $container->get('db')->table('guides')->where('id', '=', $id)->where('author', '=', $token->sub)->first();
        return withCORSHeaders($resp)->withJson($guide);
    });

    $app->post('/guides/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $id = $args['id'];
        $guide = $req->getParsedBody();
        $container->get('db')->table('guides')->where('id', '=', $id)->where('author', '=', $token->sub)->update($guide);
        return withCORSHeaders($resp)->withJson($guide);
    });

    $app->post('/guides', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $body = $req->getParsedBody();
        $container->get('db')->table('guides')->insert(array_merge(
            $body,
            [ 'author' => $token->sub ]
        ));
        return withCORSHeaders($resp)->withJson($body);
    });

    // TOURS

    $app->post('/tours', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $body = $req->getParsedBody();
        $container->get('db')->table('tours')->insert([
            'id' => $body['id'],
            'author' => $token->sub,
            'name' => $body['name'],
            'date' => $body['date'],
            'price' => intval($body['price'], 10),
            'description' => $body['description'],
            'count' => intval($body['count'], 10),
            'details' => $body['details'],
            'shedule' => $body['shedule'],
            'guide' => $body['guide'],
            'phone' => $body['phone'],
            'pickpoint_address' => $body['pickpoint']['address'],
            'pickpoint_comment' => $body['pickpoint']['comment'],
            'pickpoint_coordinates' => $body['pickpoint']['coordinates'][0] . ',' . $body['pickpoint']['coordinates'][1],
            'pickpoint_time' => $body['pickpoint']['time'],
            'placement_id' => $body['placement']['id']
        ]);

        foreach ($body['placement']['placements'] as $placement) {
            $container->get('db')->table('placement_items')->insert([
                'id' => $placement['id'],
                'placement_id' => $body['placement']['id'],
                'type' => $placement['type'],
                'link' => $placement['link'],
                'post_id' => intval($placement['postId'], 10),
                'category_id' => intval($placement['categoryId'], 10),
                'include_children' => $placement['includeChildren'],
                'title' => $placement['title'],
                'tag_id' => intval($placement['tagId'], 10),
                'name' => $placement['name'],
                'query' => $placement['query']
            ]);
        }

        return withCORSHeaders($resp)->withJson($body);
    });

    $app->get('/tours', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $tours = $container->get('db')->table('tours')->where('author', '=', $token->sub)->get();
        $results = array();
        foreach ($tours as $tour) {
            $placementItems = $container->get('db')->table('placement_items')->where('placement_id', '=', $tour->placement_id)->get();
            array_push($results, [
                'id' => $tour->id,
                'name' => $tour->name,
                'date' => $tour->date,
                'price' => $tour->price,
                'description' => $tour->description,
                'count' => $tour->count,
                'details' => $tour->details,
                'shedule' => $tour->shedule,
                'guide' => $tour->guide,
                'phone' => $tour->phone,
                'pickpoint' => [
                    'address' => $tour->pickpoint_address,
                    'comment' => $tour->pickpoint_comment,
                    'coordinates' => splitCoordinates($tour->pickpoint_coordinates),
                    'time' => $tour->pickpoint_time
                ],
                'placement' => [
                    'id' => $tour->placement_id,
                    'placements' => $placementItems->map(function($placement) {
                        switch ($placement->type) {
                            case 'link':
                                return [
                                    'id' => $placement->id,
                                    'type' => $placement->type,
                                    'link' => $placement->link
                                ];
                            case 'article':
                                return [
                                    'id' => $placement->id,
                                    'type' => $placement->type,
                                    'postId' => $placement->post_id,
                                    'title' => $placement->title
                                ];
                            case 'category':
                                return [
                                    'id' => $placement->id,
                                    'type' => $placement->type,
                                    'categoryId' => $placement->category_id,
                                    'name' => $placement->name,
                                    'includeChildren' => $placement->include_children === 1
                                ];
                            case 'tag':
                                return [
                                    'id' => $placement->id,
                                    'type' => $placement->type,
                                    'tagId' => $placement->tag_id,
                                    'name' => $placement->name
                                ];
                            case 'search':
                                return [
                                    'id' => $placement->id,
                                    'type' => $placement->type,
                                    'query' => $placement->query
                                ];
                        }
                    })
                ]
            ]);
        }
        return withCORSHeaders($resp)->withJson($results);
    });

    $app->get('/tours/least_recent_update_placement_time', function (Request $req, Response $resp, array $args) use ($container) {
        $tour = $container->get('db')->table('tours')->orderBy('update_placement_time', 'DESC')->first();
        $placementItems = $container->get('db')->table('placement_items')->where('placement_id', '=', $tour->placement_id)->get();
        $result = [
            'id' => $tour->id,
            'placement' => [
                'id' => $tour->placement_id,
                'date' => $tour->date,
                'pickpoint' => [
                    'time' => $tour->pickpoint_time
                ],
                'placements' => $placementItems->map(function($placement) {
                    switch ($placement->type) {
                        case 'link':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'link' => $placement->link
                            ];
                        case 'article':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'postId' => $placement->post_id,
                                'title' => $placement->title
                            ];
                        case 'category':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'categoryId' => $placement->category_id,
                                'name' => $placement->name,
                                'includeChildren' => $placement->include_children === 1
                            ];
                        case 'tag':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'tagId' => $placement->tag_id,
                                'name' => $placement->name
                            ];
                        case 'search':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'query' => $placement->query
                            ];
                    }
                })
            ]
        ];
        return $resp->withJson($result);
    });

    $app->get('/tours/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $id = $args['id'];
        $tour = $container->get('db')->table('tours')->where('id', '=', $id)->where('author', '=', $token->sub)->first();
        $placementItems = $container->get('db')->table('placement_items')->where('placement_id', '=', $tour->placement_id)->get();
        $result = [
            'id' => $tour->id,
            'name' => $tour->name,
            'date' => $tour->date,
            'price' => $tour->price,
            'description' => $tour->description,
            'count' => $tour->count,
            'details' => $tour->details,
            'shedule' => $tour->shedule,
            'guide' => $tour->guide,
            'phone' => $tour->phone,
            'pickpoint' => [
                'address' => $tour->pickpoint_address,
                'comment' => $tour->pickpoint_comment,
                'coordinates' => splitCoordinates($tour->pickpoint_coordinates),
                'time' => $tour->pickpoint_time
            ],
            'placement' => [
                'id' => $tour->placement_id,
                'placements' => $placementItems->map(function($placement) {
                    switch ($placement->type) {
                        case 'link':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'link' => $placement->link
                            ];
                        case 'article':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'postId' => $placement->post_id,
                                'title' => $placement->title
                            ];
                        case 'category':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'categoryId' => $placement->category_id,
                                'name' => $placement->name,
                                'includeChildren' => $placement->include_children === 1
                            ];
                        case 'tag':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'tagId' => $placement->tag_id,
                                'name' => $placement->name
                            ];
                        case 'search':
                            return [
                                'id' => $placement->id,
                                'type' => $placement->type,
                                'query' => $placement->query
                            ];
                    }
                })
            ]
        ];
        return withCORSHeaders($resp)->withJson($result);
    });
    
    $app->post('/tours/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $id = $args['id'];
        $body = $req->getParsedBody();
        $container->get('db')->table('tours')->where('id', '=', $id)->update([
            'id' => $body['id'],
            'author' => $token->sub,
            'name' => $body['name'],
            'date' => $body['date'],
            'price' => intval($body['price'], 10),
            'description' => $body['description'],
            'count' => intval($body['count'], 10),
            'details' => $body['details'],
            'shedule' => $body['shedule'],
            'guide' => $body['guide'],
            'phone' => $body['phone'],
            'pickpoint_address' => $body['pickpoint']['address'],
            'pickpoint_comment' => $body['pickpoint']['comment'],
            'pickpoint_coordinates' => $body['pickpoint']['coordinates'][0] . ',' . $body['pickpoint']['coordinates'][1],
            'pickpoint_time' => $body['pickpoint']['time'],
            'placement_id' => $body['placement']['id']
        ]);

        $container->get('db')->table('placement_items')->where('placement_id', $body['placement']['id'])->delete();

        foreach ($body['placement']['placements'] as $placement) {
            $container->get('db')->table('placement_items')->insert([
                'id' => $placement['id'],
                'placement_id' => $body['placement']['id'],
                'type' => $placement['type'],
                'link' => $placement['link'],
                'post_id' => intval($placement['postId'], 10),
                'category_id' => intval($placement['categoryId'], 10),
                'include_children' => $placement['includeChildren'],
                'title' => $placement['title'],
                'tag_id' => intval($placement['tagId'], 10),
                'name' => $placement['name'],
                'query' => $placement['query']
            ]);
        }

        return withCORSHeaders($resp)->withJson($body);
    });

    $app->post('/tours/{id}/update_placement_time', function (Request $req, Response $resp, array $args) use ($container) {
        $id = $args['id'];
        $tour = $container->get('db')->table('tours')->where('id', '=', $id)->update([
            'update_placement_time' => time()
        ]);
        return $resp->withStatus(200);
    });

    $app->delete('/tours/{id}', function (Request $req, Response $resp, array $args) use ($container) {
        $token = parseToken($container, $req);
        $id = $args['id'];
        $tour = $container->get('db')->table('tours')->where('id', '=', $id)->where('author', '=', $token->sub)->first();
        $container->get('db')->table('placement_items')->where('placement_id', '=', $tour->placement_id)->delete();
        $container->get('db')->table('tours')->where('id', '=', $id)->where('author', '=', $token->sub)->delete();
        return withCORSHeaders($resp)->withStatus(200);
    });
    
    $app->get('/tours/{id}/posts', function (Request $req, Response $resp, array $args) use ($container) {
        $id = $args['id'];
        $tour_posts = $container->get('db')->table('tour_post')->where('tour_id', '=', $id)->get();
        $results = $tour_posts->map(function ($tour_post) {
            return $tour_post->post_id;
        });
        return $resp->withJson($results);
    });

    $app->post('/tours/{tour_id}/posts', function (Request $req, Response $resp, array $args) use ($container) {
        $tour_id = $args['tour_id'];
        $post_id = $req->getBody();
        $container->get('db')->table('tour_post')->insert([
            'tour_id' => $tour_id,
            'post_id' => $post_id
        ]);
        return $resp->withStatus(200);
    });

    $app->delete('/tours/{tour_id}/posts/{post_id}', function (Request $req, Response $resp, array $args) use ($container) {
        $tour_id = $args['tour_id'];
        $post_id = $args['post_id'];
        $container->get('db')->table('tour_post')->where('tour_id', '=', $tour_id)->where('post_id', '=', $post_id)->delete();
        return $resp->withStatus(200);
    });

    // POST

    $app->get('/posts/{id}/tours', function (Request $req, Response $resp, array $args) use ($container) {
        $id = $args['id'];
        $tour_posts = $container->get('db')->table('tour_post')->where('post_id', '=', $id)->get();
        $tour_ids = $tour_posts->map(function ($tour_post) {
            return $tour_post->tour_id;
        })->toArray();
        $tour_ids = array_unique($tour_ids);
        $results = array();
        foreach ($tour_ids as $tour_id) {
            $tour = $container->get('db')->table('tours')->where('id', '=', $tour_id)->first();
            $guide = $container->get('db')->table('guides')->where('id', '=', $tour->guide)->first();
            if ($tour) {
                array_push($results, [
                    'id' => $tour->id,
                    'name' => $tour->name,
                    'date' => $tour->date,
                    'price' => intval($tour->price, 10),
                    'description' => $tour->description,
                    'count' => intval($tour->count, 10),
                    'details' => $tour->details,
                    'shedule' => $tour->shedule,
                    'guide' => [
                        'name' => $guide->name,
                        'description' => $guide->description
                    ],
                    'phone' => $tour->phone,
                    'pickpoint' => [
                        'address' => $tour->pickpoint_address,
                        'comment' => $tour->pickpoint_comment,
                        'coordinates' => splitCoordinates($tour->pickpoint_coordinates),
                        'time' => $tour->pickpoint_time
                    ]
                ]);
            }
        }
        return withCORSHeaders($resp)->withJson($results);
    });
};
