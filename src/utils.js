/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* hex/bytes and string/bytes conversion functions */

var Utils = function() {
    "use strict";

    var Utils = {
        bytestohex: function(b) {
            var s = "",
                ch, i;

            for (i = 0; i < b.length; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);
            }

            return s;
        },

        hextobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i += 2) {
                b.push(parseInt(s.substr(i, 2), 16));
            }

            return b;
        },

        bytestostring: function(b) {
            return String.fromCharCode.apply(String,b);
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        }
    };

    return Utils;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.Utils = Utils;
}
